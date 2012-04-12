#!/bin/sh
#
# RemoveFlashback.sh
#   -- Flashback removal tool --
#    Based on a script by Yoshioka Tsuneo:
#      https://github.com/yoshiokatsuneo/RemoveFlashback
#    and changes by F-Secure at:
#       https://www.f-secure.com/weblog/archives/00002346.html
#
#
# Ref:
#   F-Secure Weblog - Mac Flashback Infections
#   http://www.f-secure.com/weblog/archives/00002345.html
#

PATH="/usr/bin:/bin:/usr/sbin:/sbin"
timestamp=`date '+%Y%m%d-%H%M%S'`
infected=0
tmpfilename_base=/tmp/RemoveFlashback.$$

quar_dir=${tmpfilename_base}.quarantine

string1="slfp"
string2="cfinh"

string3="ksyms"
string4="__ldpath__"

mkdir -p "$quar_dir"

# for the LaunchAgent:
#  * Check that binary start with "."
#
#    * (permission is 777)
#    * has StartInterval (4212)
#    * StandardOutput and Error is /dev/null
#
#

safari_plist_base="/Applications/Safari.app/Contents/Info"
firefox_plist_base="/Applications/Firefox.app/Contents/Info"
#safari_plist_base="`pwd`/test-Info"
macosx_environment_plist="${HOME}/.MacOSX/environment"
#macosx_environment_plist="${HOME}/work/RemoveFlashback/test-environment"

if [ "$1" = "scanonly" ]; then
    scanonly=true
    echo "------- Scanonly mode"
else
    scanonly=false
    echo "------- Quarantine mode"
fi

# Check if we are effectively root
if [ "$EUID" -eq "0" ]; then
    adminmode=true
    echo "------- Admin mode"
    scanonly=true
    echo "------- Scanonly mode (FORCED)"
else
    adminmode=false
    echo "------- User mode"
fi

files_to_quarantine=/tmp/FS_to_quarantine
rm -f $files_to_quarantine

quarantine_later() {
    echo "$1" >> $files_to_quarantine
}

quarantine() {
    $scanonly && return
    if ! [ -e "$files_to_quarantine" ] ; then
        echo "Nothing to quarantine."
        return
    fi
    echo "Quarantining files:"
    sort $files_to_quarantine | uniq | \
    xargs -I % mv -v % "$quar_dir"
    rm -f $files_to_quarantine
}

zip_quarantine() {
    zipfile="${HOME}/flashback_quarantine.zip"
    zip -rq -e --password infected $zipfile ${quar_dir}
    rm -rf "${quar_dir}"
    chown $USER $zipfile
    echo "Quarantined files stored in password-protected zip file $zipfile"
}

is_malicious() {
    file="$1"
    echo "Checking file $file"
    if file_is_signed "$file" ; then
	echo " - File $file is signed"
	return 1
    fi
    # libraries whose name starts with . are bad
    filename=`basename "$file"`
    if echo $filename | grep -q '^\.' ; then
	echo " - File $file has a bad name"
	return 0
    fi
    if grep -q "${string1}" "$file" && grep -q "${string2}" "$file" ; then
	echo " - File $file matches patterns 1 & 2"
	return 0
    fi
    if grep -q "${string3}" "$file" && grep -q "${string4}" "$file" ; then
	echo " - File $file matches patterns 3 & 4"
	return 0
    fi
    return 1
}

check_launchagent()
{
    for plist in ~/Library/LaunchAgents/* ; do 
        prop=`echo $plist | sed -e 's/\.plist$//'`
        pathname=`defaults read $prop ProgramArguments 2> /dev/null | head -2 | tail -1 | sed -e 's/.*"\(.*\)".*/\1/'`
        if [ -z "$pathname" ] ; then
            continue
        fi
        filename=`basename "$pathname"`
        if echo $filename | grep -q '^\.' ; then
            infected=1
        if $scanonly; then
                echo "File $pathname is most likely Flashback"
        else
                echo "File $pathname is most likely Flashback -- removing"
            quarantine_later "$pathname"
                quarantine_later "$plist"
        fi
        fi
    done
}
check_all_user_launchagent()
{
    for userDir in /Users/*; do
        for plist in $userDir/Library/LaunchAgents/* ; do 
            prop=`echo $plist | sed -e 's/\.plist$//'`
            pathname=`defaults read $prop ProgramArguments 2> /dev/null | head -2 | tail -1 | sed -e 's/.*"\(.*\)".*/\1/'`
            if [ -z "$pathname" ] ; then
                continue
            fi
            filename=`basename "$pathname"`
            if echo $filename | grep -q '^\.' ; then
                infected=1
            if $scanonly; then
                    echo "File $pathname is most likely Flashback"
            else
                    echo "File $pathname is most likely Flashback -- removing"
                quarantine_later "$pathname"
                    quarantine_later "$plist"
            fi
            fi
        done
    done
}
file_is_signed() {
    codesign -R="anchor trusted" -v "$1" 2> /dev/null
}

check_libraries()
{
    plist_base="$1"
    libraries="$2"
    
    rm -f /tmp/infected
    grep -a -o '__ldpath__[ -~]*' "${libraries}" | while read line; do
        ldpath=${line/#__ldpath__/}
        if [ -f "$ldpath" ]; then
            if [ -x "$ldpath" ] && is_malicious "$ldpath" ; then
                echo "Infected file (check 1): ${ldpath}"
                $scanonly || quarantine_later "${ldpath}"
                touch /tmp/infected
            fi
        fi
    done
    if [ -f /tmp/infected ] ; then
        infected=1
        rm /tmp/infected
    fi
    
    if is_malicious "$libraries" ; then
        $scanonly || quarantine_later "$libraries"
        infected=1
    fi
    
}

check_browser_plist(){
    local plist_base=$1
    
    if ! [ -e "${plist_base}.plist" ]; then return 0; fi
    if ! defaults read "${plist_base}" LSEnvironment > "${tmpfilename_base}.plist" 2>/dev/null ]; then
        return 0
    fi
    libraries=$(defaults read "${tmpfilename_base}" "DYLD_INSERT_LIBRARIES")
    if [ $? -eq 0 ]; then
        check_libraries "${plist_base}" "$libraries"
    fi
    echo "Found DYLD_INSERT_LIBRARIES in ${plist_base}.plist LSEnvironment: $libraries"
    infected=1
    if ! $scanonly; then
        echo "Removing..."
        sudo cp -vp "${plist_base}.plist" "${quar_dir}"
        sudo defaults delete "${plist_base}" LSEnvironment
        sudo chmod 644 "${plist_base}.plist"
        if [ -f "$libraries" ] ; then
            quarantine_later "$libraries"
        fi
    fi
}

dont_do() {
    echo "NOT DOING: $@"
}


check_macosx_environment_plist()
{
    local plist_base=$1
    
    if ! [ -e "${plist_base}.plist" ]; then return 0; fi
    libraries=$(defaults read "${plist_base}" "DYLD_INSERT_LIBRARIES" 2>/dev/null)
    if [ "$?" -ne "0" ]; then
        return 0
    fi
    check_libraries "${plist_base}" "$libraries"
    echo "Found DYLD_INSERT_LIBRARIES in ${plist_base}.plist: $libraries"
    if ! $scanonly;then
        echo "Removing..."
        cp -vp "${plist_base}.plist" "${quar_dir}"
        defaults delete "${plist_base}" DYLD_INSERT_LIBRARIES
        [ -f ${plist_base}.plist ] && chown $USER ${plist_base}.plist
        if [ -f "$libraries" ] ; then
            quarantine_later "$libraries"
            infected=1
        fi
    fi
}

path_contains_malware() {
    path="$1"
    rm -f /tmp/bad_element
    echo "$path" | tr : "\n" | while read part ; do
	if is_malicious "$part" ; then
	    echo "$part" >> /tmp/bad_element
	fi
    done
    if [ -s /tmp/bad_element ] ; then
	return 0
    fi
    return 1
}


global_dyld=`launchctl getenv DYLD_INSERT_LIBRARIES`
if [ -n "$global_dyld" ] && path_contains_malware "$global_dyld" ; then
    infected=1
    echo "Found DYLD_INSERT_LIBRARIES in launchctl environment ($global_dyld)."
    if ! $scanonly; then
        echo "Removing..."
        launchctl unsetenv DYLD_INSERT_LIBRARIES
    fi
fi

if $adminmode; then
    check_all_user_launchagent
else
    check_launchagent   
fi
check_browser_plist "${safari_plist_base}"
if ! $scanonly; then
    touch /Applications/Safari.app
fi
check_browser_plist "${firefox_plist_base}"
if ! $scanonly; then
    [ -d /Applications/Firefox.app ] && touch /Applications/Firefox.app
fi

if $adminmode; then
    for userDir in /Users/*; do
        check_macosx_environment_plist "${userDir}/.MacOSX/environment"
    done
else
    check_macosx_environment_plist "${macosx_environment_plist}"
fi
quarantine

if [ -f "${tmpfilename_base}.plist" ]; then
    rm "${tmpfilename_base}.plist"
fi

if [ "$infected" -eq "0" ];then
    echo "No Flashback malware found."
else
    if ! $scanonly; then
    	zip_quarantine
    	if "$0" scanonly; then
    	    echo "Your system has been cleaned."
            infected=0
    	else
    	    echo "There has been a problem and your system is still infected."
            infected=2
    	fi
    fi
fi

exit $infected



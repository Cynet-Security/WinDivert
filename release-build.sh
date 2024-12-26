#!/bin/bash
#
# release-build.sh
# (C) 2019, all rights reserved,
#
# This file is part of CyDivert.
#
# CyDivert is free software: you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
# License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# CyDivert is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 2 of the License, or (at your option)
# any later version.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
# 
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#
# Script for building CyDivert binary packages.  This script assumes the
# binaries are already built and are in the install/ subdirectory.

set -e

LABEL=
if [ $# -ge 1 ]
then
    LABEL="-$1"
fi

TARGET=MINGW

CYDIVERT32_SYS=install/$TARGET/i386/CyDivert32.sys
if [ $# -ge 2 ]
then
    CYDIVERT32_SYS=$2
fi

CYDIVERT64_SYS=install/$TARGET/amd64/CyDivert64.sys
if [ $# -ge 3 ]
then
    CYDIVERT64_SYS=$3
fi

VERSION=`cat ./VERSION`
NAME=CyDivert-$VERSION

echo "BUILD $NAME$LABEL"
INSTALL=install/$NAME$LABEL
echo "\tmake $INSTALL..."
rm -rf $INSTALL
mkdir -p $INSTALL
echo "\tcopy $INSTALL/README..."
cp README $INSTALL
echo "\tcopy $INSTALL/CHANGELOG..."
cp CHANGELOG $INSTALL
echo "\tcopy $INSTALL/LICENSE..."
cp LICENSE $INSTALL
echo "\tcopy $INSTALL/VERSION..."
cp VERSION $INSTALL
echo "\tmake $INSTALL/include..."
mkdir -p $INSTALL/include
echo "\tcopy $INSTALL/include/cydivert.h..."
cp include/cydivert.h $INSTALL/include
echo "\tmake $INSTALL/doc..."
mkdir -p $INSTALL/doc
echo "\tcopy $INSTALL/doc/CyDivert.html..."
cp doc/cydivert.html $INSTALL/doc/CyDivert.html
echo "\tmake $INSTALL/x86..."
mkdir -p $INSTALL/x86
echo "\tcopy $INSTALL/x86/CyDivert32.sys..."
cp "$CYDIVERT32_SYS" $INSTALL/x86
if ! grep "DigiCert High Assurance EV Root" $INSTALL/x86/CyDivert32.sys \
    2>&1 >/dev/null
then
    echo "\t\033[33mWARNING\033[0m: unsigned CyDivert32.sys..."
fi
if [ -e "$CYDIVERT64_SYS" ]
then
    echo "\tcopy $INSTALL/x64/CyDivert64.sys..."
    cp "$CYDIVERT64_SYS" $INSTALL/x86
fi
echo "\tcopy $INSTALL/x86/CyDivert.lib..."
cp install/$TARGET/i386/CyDivert.lib $INSTALL/x86
echo "\tcopy $INSTALL/x86/CyDivert.dll..."
cp install/$TARGET/i386/CyDivert.dll $INSTALL/x86
echo "\tcopy $INSTALL/x86/netdump.exe..."
cp install/$TARGET/i386/netdump.exe $INSTALL/x86
echo "\tcopy $INSTALL/x86/netfilter.exe..."
cp install/$TARGET/i386/netfilter.exe $INSTALL/x86
echo "\tcopy $INSTALL/x86/passtru.exe..."
cp install/$TARGET/i386/passthru.exe $INSTALL/x86
echo "\tcopy $INSTALL/x86/webfilter.exe..."
cp install/$TARGET/i386/webfilter.exe $INSTALL/x86
echo "\tcopy $INSTALL/x86/streamdump.exe..."
cp install/$TARGET/i386/streamdump.exe $INSTALL/x86
echo "\tcopy $INSTALL/x86/flowtrack.exe..."
cp install/$TARGET/i386/flowtrack.exe $INSTALL/x86
echo "\tcopy $INSTALL/x86/socketdump.exe..."
cp install/$TARGET/i386/socketdump.exe $INSTALL/x86
echo "\tcopy $INSTALL/x86/cydivertctl.exe..."
cp install/$TARGET/i386/cydivertctl.exe $INSTALL/x86
echo "\tcopy $INSTALL/x86/test.exe..."
cp install/$TARGET/i386/test.exe $INSTALL/x86
if [ -d "install/$TARGET/amd64" ]
then
    echo "\tmake $INSTALL/amd64..."
    mkdir -p $INSTALL/x64
    echo "\tcopy $INSTALL/amd64/CyDivert64.sys..."
    cp "$CYDIVERT64_SYS" $INSTALL/x64
    if ! grep "DigiCert High Assurance EV Root" \
        $INSTALL/x64/CyDivert64.sys 2>&1 >/dev/null
    then
        echo "\t\033[33mWARNING\033[0m: unsigned CyDivert64.sys..."
    fi
    echo "\tcopy $INSTALL/x64/CyDivert.lib..."
    cp install/$TARGET/amd64/CyDivert.lib $INSTALL/x64
    echo "\tcopy $INSTALL/x64/CyDivert.dll..."
    cp install/$TARGET/amd64/CyDivert.dll $INSTALL/x64
    echo "\tcopy $INSTALL/x64/netdump.exe..."
    cp install/$TARGET/amd64/netdump.exe $INSTALL/x64
    echo "\tcopy $INSTALL/x64/netfilter.exe..."
    cp install/$TARGET/amd64/netfilter.exe $INSTALL/x64
    echo "\tcopy $INSTALL/x64/passtru.exe..."
    cp install/$TARGET/amd64/passthru.exe $INSTALL/x64
    echo "\tcopy $INSTALL/x64/webfilter.exe..."
    cp install/$TARGET/amd64/webfilter.exe $INSTALL/x64
    echo "\tcopy $INSTALL/x64/streamdump.exe..."
    cp install/$TARGET/amd64/streamdump.exe $INSTALL/x64
    echo "\tcopy $INSTALL/x64/flowtrack.exe..."
    cp install/$TARGET/amd64/flowtrack.exe $INSTALL/x64
    echo "\tcopy $INSTALL/x64/socketdump.exe..."
    cp install/$TARGET/amd64/socketdump.exe $INSTALL/x64
    echo "\tcopy $INSTALL/x64/cydivertctl.exe..."
    cp install/$TARGET/amd64/cydivertctl.exe $INSTALL/x64
    echo "\tcopy $INSTALL/x64/test.exe..."
    cp install/$TARGET/amd64/test.exe $INSTALL/x64
else
    echo "\tWARNING: skipping missing AMD64 build..."
fi
PACKAGE=$NAME$LABEL.zip
echo "\tbuilding $PACKAGE..."
(
    cd install;
    zip -r $PACKAGE $NAME$LABEL > /dev/null
)
echo -n "\tclean $INSTALL..."
rm -rf $INSTALL
echo "DONE"


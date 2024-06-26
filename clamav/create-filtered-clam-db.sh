#!/bin/bash
set -x

# Create a temporary directory:
mkdir -p tmp

# Get into it
pushd tmp

# Check if main.cvd exists
if [ -f ~/.cvdupdate/database/main.cvd ]
then
    echo "main.cvd already exists"
    cp ~/.cvdupdate/database/main.cvd .
else
    echo "main.cvd does not exist, downloading it"
    rm -rf ~/.cvdupdate
    python3 -m pip install --user cvdupdate --break-system-packages
    python3 -m cvdupdate update -V
    return_code=$?
    if [ $return_code -ne 0 ]
    then
        echo "Failed to download main.cvd (http code: $return_code)"
        exit 1
    fi
    cp ~/.cvdupdate/database/main.cvd .
fi


# unpack the main.cvd
sigtool --unpack main.cvd
if [ $? -ne 0 ]
then
    echo "Failed to unpack main.cvd"
    exit 1
fi
rm main.cvd

# Loop over all the files in the tmp directory
for file in *
do
    # If the file has one line, skip
    if [ $(wc -l < $file) -eq 1 ]
    then
        echo "Skipping $file"
        continue
    fi

    # If the file is the COPYING or main.cvd file, skip
    if [ $(basename $file) == "main.cvd" ]
    then
        echo "Skipping $file"
        continue
    fi
    if [ $(basename $file) == "COPYING" ]
    then
        echo "Skipping $file"
        continue
    fi

    # Filter out the lines that does not contain the word "Unix" or "Multios"
    grep -v -E "Win\.|Osx\." $file > $file.tmp
    mv $file.tmp $file
    # If the file is empty, delete it
    if [ $(wc -l < $file) -eq 0 ]
    then
        echo "Deleting $file"
        rm $file
    fi
done


sigtool --version
printf "slashben\n" | sigtool --build=main.cud --unsigned
if [ $? -ne 0 ]
then
    echo "Failed to build main.cud"
    exit 1
fi


# Get back
popd

cp tmp/main.cud main.cud

# Clean up
rm -rf tmp

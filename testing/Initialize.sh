# If bin directory doesn't exist, then create it.
if [ ! -d ../bin ]; then
    mkdir ../bin
    echo Created ../bin directory 
fi 

# If bin directory doesn't exist, then create it.
if [ ! -d ../res ]; then
    mkdir ../res
    echo Created ../res directory 
fi 

# Unpack and build ArgParsing
ArgParsingVer=1.3.1
wget -O ../res/ArgParsing_v$ArgParsingVer.tar.gz https://github.com/krmnino/ArgParsing/archive/refs/tags/v$ArgParsingVer.tar.gz
tar -xvzf ../res/ArgParsing_v$ArgParsingVer.tar.gz --directory ../res
rm -r ../res/ArgParsing_v$ArgParsingVer.tar.gz
cd ../res/ArgParsing-$ArgParsingVer/src
sh Initialize.sh
cd -
make -C ../res/ArgParsing-$ArgParsingVer/src
cp ../res/ArgParsing-$ArgParsingVer/src/ArgParsing_C.h ../res
cp ../res/ArgParsing-$ArgParsingVer/res/libArgParsing.so ../res
rm -r ../res/ArgParsing-$ArgParsingVer

# Unpack and build Randomizer
RandomizerVer=1.4.1
wget -O ../res/Randomizer_v$RandomizerVer.tar.gz https://github.com/krmnino/Randomizer/archive/refs/tags/v$RandomizerVer.tar.gz
tar -xvzf ../res/Randomizer_v$RandomizerVer.tar.gz --directory ../res
rm -r ../res/Randomizer_v$RandomizerVer.tar.gz
cd ../res/Randomizer-$RandomizerVer/src
sh Initialize.sh
cd -
make -C ../res/Randomizer-$RandomizerVer/src
cp ../res/Randomizer-$RandomizerVer/src/Randomizer_C.h ../res
cp ../res/Randomizer-$RandomizerVer/res/libRandomizer.so ../res
rm -r ../res/Randomizer-$RandomizerVer

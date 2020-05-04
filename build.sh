#! /bin/sh
make clean 2> /dev/null
mkdir output 2> /dev/null
rm output/enumy 2> /dev/null 

if [ "$1" == "32bit" ]; then
    echo "building in 32 bit mode"
    rm ./output/enumy32 2> /dev/null
    docker build -t enumy_environment -f docker/Dockerfile.32bit . 
    docker container rm enumy_temp 
    docker container create --name enumy_temp enumy_environment 
    docker container cp enumy_temp:/build/output/enumy ./output/enumy32
    docker container rm enumy_temp
    file output/enumy32
    ldd output/enumy32
    
elif [ "$1" == "64bit" ]; then
    echo "building in 64 bit mode"
    rm ./output/enumy64 2> /dev/null
    docker build -t enumy_environment -f docker/Dockerfile.64bit . 
    docker container rm enumy_temp 
    docker container create --name enumy_temp enumy_environment 
    docker container cp enumy_temp:/build/output/enumy ./output/enumy64
    docker container rm enumy_temp
    file output/enumy64
    ldd output/enumy64

elif [ "$1" == "arm64v8" ]; then
    echo "building in arm64v8 bit mode"
    rm ./output/enumy64 2> /dev/null
    docker build -t enumy_environment -f docker/Dockerfile.arm64v8 . 
    docker container rm enumy_temp 
    docker container create --name enumy_temp enumy_environment 
    docker container cp enumy_temp:/build/output/enumy ./output/enumyArm64V8
    docker container rm enumy_temp
    file output/enumyArm64V8
    ldd output/enumyArm64V8
elif [ "$1" == "all" ]; then
    ./build.sh 32bit
    ./build.sh 64bit
else
    echo "USAGE:"
    echo "  ./build.sh 32bit"
    echo "  ./build.sh 64bit"
    echo "  ./build.sh arm64v8"
    echo "  ./build.sh all"
    exit
fi

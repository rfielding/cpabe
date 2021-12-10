#!/bin/bash

rm -rf trusted
go build -o ibe

./ibe ca trusted jlkadlkjqfvklj4ty890zadsx2x3euhi23exhui23ehxui23eiuh23xeuhi23ehxu2i3exhu2iehi
./ibe issue trusted rob.fielding@gmail.com
./ibe lock trusted rob.fielding@gmail.com
./ibe unlock trusted rob.fielding@gmail.com
cat trusted/*

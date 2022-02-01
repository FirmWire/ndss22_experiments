#!/bin/sh

git submodule init || true
git submodule update || true
cd AFLplusplus
# We don'nee to checkout 3.13 since it's already set in the submodule.
# git checkout f66a4de18a013eeb1aed27a9e38e8209ce168c1c
make -j`nproc`
cd unicorn_mode
git submodule init unicornafl
git submodule update unicornafl
cd unicornafl
# we need the latest unicornafl bindings
git checkout 1c47d1ebc7e904ad4efc1370f23e269fb9ac3f93
make

echo "done"

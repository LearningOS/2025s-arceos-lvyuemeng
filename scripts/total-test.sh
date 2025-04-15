#!/bin/bash

score=0

if ./scripts/test-print.sh ; then
    ((score += 100))
fi

if ./scripts/test-ramfs_rename.sh ; then
    ((score += 100))
fi

if ./scripts/test-alt_alloc.sh ; then
    ((score += 100))
fi

if ./scripts/test-support_hashmap.sh ; then
    ((score += 100))
fi

if ./scripts/test-sys_map.sh ; then
    ((score += 100))
fi

if ./scripts/test-simple_hv.sh ; then
    ((score += 100))
fi

echo $score
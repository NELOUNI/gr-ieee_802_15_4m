#!/bin/sh
ps auxw | grep -ie 'tx_samples_from_file' | awk '{print $2}' | xargs sudo kill -9

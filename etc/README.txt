To generate the sample networking-huawei configuration files, run the
following command from the top level of the networking-huawei directory:

tox -e genconfig

If a 'tox' environment is unavailable, then you can run the following script
instead to generate the configuration files:

./tools/generate_config_file_samples.sh
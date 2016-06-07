#!/usr/bin/env bash

DIR_HUAWEI=$DEST/networking-huawei
NW_HUAWEI_AC_CONF_FILE=${NW_HUAWEI_AC_CONF_FILE:-"$NEUTRON_CONF_DIR/huawei_driver_config.ini"}



if is_service_enabled huawei-ac; then
    source $DIR_HUAWEI/devstack/ac/setup_plugin
fi

function install_networking_huawei {
    cd $DIR_HUAWEI
    sudo python setup.py install
    sudo pip install -r requirements.txt
}


if [[ "$1" == "source" ]]; then
    # no-op
    :
fi

if [[ "$1" == "stack" && "$2" == "pre-install" ]]; then
    echo "Configuring Huawei Controller plugin."


elif [[ "$1" == "stack" && "$2" == "install" ]]; then
    echo "Installing Huawei Controller plugin."
    install_networking_huawei

elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
    echo "Post config Huawei Controller plugin."

    if is_service_enabled huawei-ac; then
        echo "Post config Huawei AC plugin."
        ac_post_configure
    fi

elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
    echo "Starting Huawei Controller plugin."
fi

if [[ "$1" == "unstack" ]]; then
    echo "Stopping Huawei Controller plugin."

    cd $DIR_HUAWEI
    sudo pip uninstall -q -y networking-huawei
    sudo rm -rf build networking_huawei.egg-info
fi

if [[ "$1" == "clean" ]]; then
    cd $DEST
    sudo rm -rf networking_huawei
fi


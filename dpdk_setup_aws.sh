#! /bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

HUGEPGSZ=`cat /proc/meminfo  | grep Hugepagesize | cut -d : -f 2 | tr -d ' '`

#
# Creates hugepage filesystem.
#
create_mnt_huge()
{
	echo "Creating /mnt/huge and mounting as hugetlbfs"
	sudo mkdir -p /mnt/huge

	grep -s '/mnt/huge' /proc/mounts > /dev/null
	if [ $? -ne 0 ] ; then
		sudo mount -t hugetlbfs nodev /mnt/huge
	fi
}

#
# Removes hugepage filesystem.
#
remove_mnt_huge()
{
	echo "Unmounting /mnt/huge and removing directory"
	grep -s '/mnt/huge' /proc/mounts > /dev/null
	if [ $? -eq 0 ] ; then
		sudo umount /mnt/huge
	fi

	if [ -d /mnt/huge ] ; then
		sudo rm -R /mnt/huge
	fi
}

#
# Unloads igb_uio.ko.
#
remove_igb_uio_module()
{
	echo "Unloading any existing DPDK UIO module"
	/sbin/lsmod | grep -s igb_uio > /dev/null
	if [ $? -eq 0 ] ; then
		sudo /sbin/rmmod igb_uio
	fi
}

#
# Loads new igb_uio.ko (and uio module if needed).
#
load_igb_uio_module()
{
	if [ ! -f $RTE_SDK/$RTE_TARGET/kmod/igb_uio.ko ];then
		echo "## ERROR: Target does not have the DPDK UIO Kernel Module."
		echo "       To fix, please try to rebuild target."
		return
	fi

	remove_igb_uio_module

	/sbin/lsmod | grep -s uio > /dev/null
	if [ $? -ne 0 ] ; then
		modinfo uio > /dev/null
		if [ $? -eq 0 ]; then
			echo "Loading uio module"
			sudo /sbin/modprobe uio
		fi
	fi

	# UIO may be compiled into kernel, so it may not be an error if it can't
	# be loaded.
    
    # In mainline version of igb_uio (in DPDK repo) it must be enabled by loading 
    # module with wc_activate=1 flag 
    # reference https://dpdk-power-docs.readthedocs.io/en/stable/nics/ena.html

	echo "Loading DPDK UIO module"
	sudo /sbin/insmod $RTE_SDK/$RTE_TARGET/kmod/igb_uio.ko wc_activate=1
	if [ $? -ne 0 ] ; then
		echo "## ERROR: Could not load kmod/igb_uio.ko."
		quit
	fi
}

#
# Removes all reserved hugepages.
#
clear_huge_pages()
{
	echo > .echo_tmp
	for d in /sys/devices/system/node/node? ; do
		echo "echo 0 > $d/hugepages/hugepages-${HUGEPGSZ}/nr_hugepages" >> .echo_tmp
	done
	echo "Removing currently reserved hugepages"
	sudo sh .echo_tmp
	rm -f .echo_tmp

	remove_mnt_huge
}

#
# Creates hugepages.
#
set_non_numa_pages()
{
	clear_huge_pages

	echo ""
	echo "  Input the number of ${HUGEPGSZ} hugepages"
	echo "  Example: to have 128MB of hugepages available in a 2MB huge page system,"
	echo "  enter '64' to reserve 64 * 2MB pages"
	echo -n "Number of pages: "

	echo "echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-${HUGEPGSZ}/nr_hugepages" > .echo_tmp

	echo "Reserving hugepages"
	sudo sh .echo_tmp
	rm -f .echo_tmp

	create_mnt_huge
}

#
# Uses dpdk-devbind.py to move devices to work with igb_uio
#
bind_devices_to_igb_uio()
{
	if [ -d /sys/module/igb_uio ]; then
		${RTE_SDK}/usertools/dpdk-devbind.py --status
		echo ""
		echo -n "Enter PCI address of device to bind to IGB UIO driver: "
		read PCI_PATH
		sudo ${RTE_SDK}/usertools/dpdk-devbind.py -b igb_uio $PCI_PATH && echo "OK"
	else
		echo "# Please load the 'igb_uio' kernel module before querying or "
		echo "# adjusting device bindings"
	fi
}


#
# Sets up environmental variables for ICC.
#
setup_icc()
{
	DEFAULT_PATH=/opt/intel/bin/iccvars.sh
	param=$1
	shpath=`which iccvars.sh 2> /dev/null`
	if [ $? -eq 0 ] ; then
		echo "Loading iccvars.sh from $shpath for $param"
		source $shpath $param
	elif [ -f $DEFAULT_PATH ] ; then
		echo "Loading iccvars.sh from $DEFAULT_PATH for $param"
		source $DEFAULT_PATH $param
	else
		echo "## ERROR: cannot find 'iccvars.sh' script to set up ICC."
		echo "##     To fix, please add the directory that contains"
		echo "##     iccvars.sh  to your 'PATH' environment variable."
		quit
	fi
}

#
# Sets RTE_TARGET and does a "make install".
#
setup_target()
{
	export RTE_TARGET=x86_64-native-linuxapp-gcc
	make install T=${RTE_TARGET}

	echo "------------------------------------------------------------------------------"
	echo " RTE_TARGET exported as $RTE_TARGET"
	echo "------------------------------------------------------------------------------"
}

setup_target
load_igb_uio_module
set_non_numa_pages
bind_devices_to_igb_uio
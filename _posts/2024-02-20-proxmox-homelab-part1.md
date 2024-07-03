---
layout: single
title:  "Building an Active Directory Home Lab with Proxmox - Part 1"
seo_title: "Setting up and Active Directory (AD) Home Lab with Proxmox VE Part 1"
date:   2024-02-20 15:30:00 +0200
categories: ['Active-Directory', 'Homelab']
classes: wide
toc: true
---
# Objective
In this post I'll take you through the setup of my very own homelab. This process is largely for documentation purposes - a note to my future self. The goal of this project is to learn more about system administration (things like networking, firewall rules and policy management) but also to get more knowledge on how certain misconfigurations in AD can actually be introduced. In the final part of this post I will be braking into my own lab environment that I purposely misconfigured with known vulnerabilities.

# Network Setup
The idea is to create several internal segmented networks to house a few virtual machines (VMs), isolated from my home network by a firewall. As the firewall, we will use pfSense and for creating all the VMs we will use Proxmox. I'll keep things short and focus on getting a basic system up-and-running. The schematic for the eventual homelab is shown below:

![Proxmox Setup](/assets/images/homelab/proxmox-homelab.svg)

We'll create three networks behind the pfSense firewall:
- Internal network for regular machines (172.16.0.1/24)
- Cyber LAB for experimenting with vulnerable machines or data (172.16.100.1/24)
- Active Directory LAB for creating a windows only AD environment (172.16.200.1/24)

pfSense is the gateway (router) and firewall four our home lab and should always be booted first when using the lab.
{: .notice--info}

## System Requirements
- 64-bit multi-threaded CPU (minimum 4 cores) with Virtualization Support
- 16GB of RAM
- 250GB of Disk Space
- Bootable Proxmox VE drive (ISO)

# Proxmox Setup
The installation of Proxmox is relatively straight forward, so I will not include it here. If everything was successful, you should be able to reach the login portal via the IP address you specified during installation.

![login](/assets/images/homelab/proxmox-login.png)

Login with your credentials and create three new bridged interfaces alongside the default `vmbr0` interface. Your CIDR and gateway might be different.

![alt text](/assets/images/homelab/proxmox-network.png)

If you want to stay organized, you can create new pools for your networks as I did. To do this click on `Datacenter -> Permissions -> Pools -> Create`. When we create our VMs, we can then assign them to one of our pools.

To upload ISOs to Proxmox go to `lab -> local (lab) -> ISO Images -> Upload`.

## PfSense 
Create a new VM by clicking the blue box on the top right corner. Select the uploaded pfSense ISO and keep the default settings. 

After creating the VM we need to assign it our previously created bridge interfaces. Click on the VM and go to `Hardware -> Add Network Device` and select `vmbr1`. Repeat this for `vmbr2` and `vmbr3`.

Complete the installation process and reboot. Upon reboot we can configure the firewall and network. Select the following options when they appear:
- Should VLANs be set up now? `n`
- Enter the WAN interface name: `vtnet0`
- Enter the LAN interface name: `vtnet1`
- Enter the Optional 1 interface name: `vtnet2`
- Enter the Optional 2 interface name: `vtnet3`

Select option 2 and WAN:
- Configure IPv4 address WAN interface via DHCP?: `n`
- Enter the new WAN IPv4 address: `your_local_ip_of_choice`
- Enter the new WAN IPv4 subnet bit count: `your_subnet_bits`
- Enter the new WAN IPv4 upstream gateway address: `your_default_gateway`
- Configure IPv6 address WAN interface via DHCP6?: `n`
- Enter the new WAN IPv6 address: `Enter`
- Do you want to enable the DHCP server on WAN?: `n`

Select option 2 and LAN:
- Configure IPv4 address LAN interface via DHCP?: `n`
- Enter the new LAN IPv4 address: `172.16.0.1`
- Enter the new LAN IPv4 subnet bit count: `24`
- For the new LAN IPv6 address question press `Enter`
- Do you want to enable the DHCP server on LAN?: `y`
- Enter the start address of the IPv4 client address range: `172.16.0.10`
- Enter the end address of the IPv4 client address range: `172.16.0.254`

Select option 2 and OPT1:
- Configure IPv4 address OPT1 interface via DHCP?: `n`
- Enter the new OPT1 IPv4 address: `172.16.100.1`
- Enter the new OPT1 IPv4 subnet bit count: `24`
- Configure IPv6 address OPT1 interface via DHCP6: `n`
- For the new OPT1 IPv6 address question press `Enter`
- Do you want to enable the DHCP server on OPT1?: `y`
- Enter the start address of the IPv4 client address range: `172.16.100.10`
- Enter the end address of the IPv4 client address range: `172.16.100.254`
- Do you want to revert to HTTP as the webConfigurator protocol?: `n`

Select option 2 and OPT2:
- Configure IPv4 address OPT2 interface via DHCP?: `n`
- Enter the new OPT2 IPv4 address: `172.16.200.1`
- Enter the new OPT2 IPv4 subnet bit count: `24`
- Configure IPv6 address OPT2 interface via DHCP6: `n`
- For the new OPT2 IPv6 address question press `Enter`
- Do you want to enable the DHCP server on OPT2?: `n`
- Do you want to revert to HTTP as the webConfigurator protocol?: `n`

We do not setup DHCP as we will let the Domain Controller handle this for us later on.
{: .notice--info}

![alt text](/assets/images/homelab/pfsense.png)

Now we can create new hosts and assign them the `vmbr1` NIC on the LAN. From a host on the `172.16.0.1/24` network, we can access the pfSense Web Interface and proceed with the setup.

### Firewall Setup
Log into the pfSense dashboard using the credentials `admin:pfsense` and change the following settings during the setup process:
- Step 2: uncheck override DNS
- Step 4: Uncheck the `Block private networks from entering via WAN` option. Because this is not a real WAN.

Complete the remaining steps by filling out your preferred configuration settings. We can also rename our interfaces that were created by pfSense on the interface tab. 

It is useful to assign a static IPv4 address for our attacker VM. This will make it easier for us to apply firewall rules to interfaces that should only be able to reach this VM. To do this go to `Status -> DHCP Leases` and click on the `+` icon to assign a static IP to the Attacker VM. Note that this IP address should be inside the internal LAN address space.

Next go to `Firewall -> Aliases` and make a new alias with the following options:
- Name: `RFC1918`
- Description: `Private IPv4 Address Space`
- Type: `Network(s)`
- Network 1: `10.0.0.0/8`
- Network 2: `172.16.0.0/12`
- Network 3: `192.168.0.0/16`
- Network 4: `169.254.0.0/16`
- Network 5: `127.0.0.0/8`

### WAN Rules
Go to `Firewall -> Rules -> WAN -> Add` and make a new rule with the following options:
- Action: `Pass`
- Address Family: `Ipv4`
- Protocol: `TCP`
- Source: `WAN subnets`
- Destination: `Address or Alias - <pfSense IP>`
- Description: `Allow pfSense portal access from home network`

Replace the `<pfSense IP>` field with the real internal IP address of the pfSense VM (in my case `192.168.129.52`). This can be viewed at the start menu on the pfSense VM.

### LAN Rules
Go to `Firewall -> Rules -> LAN -> Add` and make a new rule with the following options:
- Action: `Block`
- Address Family: `Ipv4+IPv6`
- Protocol: `Any`
- Source: `LAN subnets`
- Destination: `WAN subnets`
- Description: `Block access to services on WAN interface`

The final LAN configuration will look something like this:

![pfsense LAN rule](/assets/images/homelab/pfsense-LAN.png)

This makes sure that the internal networks behind the WAN cannot reach our home network. If you want to connect from a device on your home network, you can add another allow rule at the top for that specific IP.

### Cyber LAB Rules
Go to `Firewall -> Rules -> Cyber Lab -> Add rule to end`:
- Address Family: `IPv4+IPv6`
- Protocol: `Any`
- Source: `Cyber Lab subnets`
- Destination: `Cyber Lab address`
- Description: `Allow traffic to all devices on the Cyber Lab network`

Add another rule to end:
- Source: `Cyber Lab subnets`
- Destination: `Address or Alias - 172.16.0.5`
- Description: `Allow traffic to Attacker VM`

Add another rule to end:
- Protocol: `Any`
- Source: `Cyber Lab subnets`
- Destination: `Address or Alias - RFC1918 (Select Invert match)`
- Description: `Allow to any non-private IPv4 Address (Internet)`

Add another rule to end:
- Action: `Block`
- Address Family: `IPv4+IPv6`
- Protocol: `Any`
- Source: `Cyber Lab subnets`
- Description: `Block access to remaining devices`

The final Cyber LAB configuration will look something like this:

![pfsense CYBER rule](/assets/images/homelab/pfsense-CYBER.png)

With these rules in place, all machines in the Cyber Lab network can reach each other and have access to the internet. They are also able to reach our attacker VM to allow further attacks.

### AD LAB Rules
Go to `Firewall -> Rules -> AD Lab -> Add rule to end`:
- Action: `Block`
- Address Family: `IPv4+IPv6`
- Protocol: `Any`
- Source: `AD Lab subnets`
- Destination: `WAN subnets`
- Description: `Block access to services on WAN interface (home network)`

Add another rule to end:
- Action: `Block`
- Address Family: `IPv4+IPv6`
- Protocol: `Any`
- Source: `AD Lab subnets`
- Destination: `Cyber Lab subnets`
- Description: `Block traffic to Cyber Lab interface`

Add another rule to end:
- Address Family: `IPv4+IPv6`
- Protocol: `Any`
- Source: `AD Lab subnets`
- Description: `Allow traffic to all other subnets and Internet`

The final AD LAB configuration will look something like this:

![pfsense CYBER rule](/assets/images/homelab/pfsense-AD.png)

This makes sure all devices in the Active Directory domain can communicate with one another. This network is isolated and managed further by the domain controllers.

Now we need to restart pfSense to persist the firewall rules. From the navigation bar select `Diagnostics -> Reboot`. Once pfSense boots up you will be redirected to the login page.

# Conclusion
At this point, we have sucessfully setup our firewall rules and segmented our network. The next step is to setup some virtual machines and add them to the internal network by selecting the right bridge interface in Proxmox. In the next part we will configure the Active Directory environment and introduce a few common vulnerabilities.
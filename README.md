# Ansible Module for Manageengine Patch Configuration
[Ansible-Galaxy collections](https://galaxy.ansible.com/nikhilpatne/manageengine) repository to create manageengine patch configurations.

## Installation

For the module to be used you need to have installed [requests](https://github.com/davidban77/gns3fy) library.

```
pip install requests
```

This collections is packaged under ansible-galaxy, so to install it you need to hit following command

```
ansible-galaxy collection install gslab.manageengine
```

## Features

- Create Patch configuration of Manageengine.


## Modules

These are the modules provided with this collection:
- `patch_configuration`: Create a manageengine patch configuration

## Examples: using the module

Here are some examples of how to use the module.



```yaml
---
- hosts: localhost
  # Call the collections to use the respective modules
  collections:
    - gslab.manageengine
  tasks:
    - name: Get the server facts
      patch_configuration:
        url: "{{ manageengine_url }}"
        port: "{{ manageengine_port }}"
        username: "{{ manageengine_username }}"
        password: "{{ manageengine_password }}"
        ip_list: "{{ ip_list }}"
        deployment_policy: "{{ deployment_policy }}"
        configuration_name: "{{ configuration_name }}"
        configuration_description: "{{ configuration_description }}"
      register: result

    - debug: var=result
```

Alternative way


```yaml
---
- hosts: localhost
  tasks:
    - name: Get the server facts
      gslab.manageengine.patch_configuration:
        url: "{{ manageengine_url }}"
        port: "{{ manageengine_port }}"
        username: "{{ manageengine_username }}"
        password: "{{ manageengine_password }}"
        ip_list: "{{ ip_list }}"
        deployment_policy: "{{ deployment_policy }}"
        configuration_name: "{{ configuration_name }}"
        configuration_description: "{{ configuration_description }}"
      register: result

    - debug: var=result
```

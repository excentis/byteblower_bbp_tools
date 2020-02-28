# ByteBlower Project Tools for Python (alpha)


## Usage

Simple tools for the manipulating a ByteBlower Project.  Currently supported actions:

- redock a port
    
      from byteblower_bbp_tools import Project
      project = Project("/path/to/file.bbp")
      port = project.get_port("CPE")
      # Dock to a ByteBlower interface
      port.dock_to_interface("byteblower.lab.excentis.com", "trunk-1-1")
      # Dock to a Wireless Endpoint with UUID 2F07097E-4297-49C5-AC0C-3FC915241BF9
      port.dock_to_wireless_endpoint("byteblower.lab.excentis.com", "2F07097E-4297-49C5-AC0C-3FC915241BF9")
      
      project.save()
 
- change the MAC address of a port
- change the IPv4 parameters of a port
- copy a frame

## Dependencies

The package depends on a few libraries:

- lxml
- scapy

Optionally it can use the ByteBlower Python API to accurately redock a port.


## Questions?

Contact us at support.byteblower@excentis.com

import binascii
import logging
from copy import deepcopy
from typing import Optional, Union  # for type hinting

from lxml import etree
from scapy.all import UDP, Ether


def _find_docking_parameters(server_address, new_docking):
    _docking_params = _get_docking_parameters_from_server(
        server_address, new_docking
    )

    if _docking_params is not None:
        # it worked, return those
        return _docking_params

    logging.warning(
        "Guessing interface parameters for {} {}.  "
        "Install the ByteBlower python API to resolve this warning".format(
            server_address, new_docking
        )
    )

    # We couldn't ask the ByteBlower Server for the port.
    # Let's take an educated guess.
    return _guess_docking_parameters(new_docking)


def _guess_docking_parameters(interface_name):
    logging.warning(
        "Guessing interface '%s' docking parameters" % interface_name
    )

    if 'nontrunk' in interface_name:
        port_id = -1
        splitted = interface_name.split('-')
        if len(splitted) == 2:
            interface_id = splitted[1]
        else:
            interface_id = -1

    elif 'trunk' in interface_name:
        splitted = interface_name.split('-')
        port_id = interface_id = -1
        if len(splitted) == 3:
            interface_id = int(splitted[1]) - 1
            port_id = int(splitted[2]) - 1
    else:
        logging.error("Unknown interface type '%s'" % interface_name)
        return None

    return interface_id, port_id


def _get_docking_parameters_from_server(server_address, interface_name):
    try:
        from byteblowerll import byteblower
    except ImportError:
        # Aargh, no API available, we can't do our job!
        logging.warning("could not find the ByteBlower API")
        return None

    connect_timeout_ns = int(1e9)  # one second

    try:
        with AutoCleanupServer(server_address,
                               timeout=connect_timeout_ns) as server:
            byteblower_interface = server.InterfaceGetByName(interface_name)

            physical_interface = byteblower_interface.GetPhysicalInterface()

            physical_id = physical_interface.IdGet()
            interface_id = byteblower_interface.PortIdGet() - 1

    except byteblower.ConfigError:
        logging.warning(
            "The ByteBlower server does not know interface '%s'" %
            interface_name
        )
        return None

    except byteblower.ByteBlowerAPIException:
        logging.warning("Could not connect to the ByteBlower server")
        return None

    return physical_id, interface_id


class ProjectParseError(Exception):

    def __init__(self, message):
        Exception.__init__(self, message)


class ElementNotFound(Exception):

    def __init__(self, message):
        Exception.__init__(self, message)


class PortNotFound(Exception):

    def __init__(self, message):
        Exception.__init__(self, message)


class FrameNotFound(Exception):

    def __init__(self, message):
        Exception.__init__(self, message)


class DockFailed(Exception):

    def __init__(self, message):
        super().__init__(message)


class FormatError(Exception):

    def __init__(self, message):
        super().__init__(message)


class AutoCleanupServer(object):
    """ Contextmanager which automatically removes the server when the object goes out of scope
        :param address: The address on which the ByteBlower server is reachable
        :type address: str
        :param port: The TCP port number on which the server listens.  9002 is the default
        :type port: int
        :param timeout: Number of nanoseconds to wait for the server to respond
        :type timeout: int
        :return: A server object
        :rtype: :class:`byteblowerll.byteblower.ByteBlowerServer`

    """

    def __init__(self, address, port=9002, timeout=int(1e9)):
        self._address = address
        self._server = None
        self._port = port
        self._timeout = timeout

    def __enter__(self):
        from byteblowerll import byteblower
        instance = byteblower.ByteBlower.InstanceGet()
        self._server = instance.ServerAdd(
            self._address, self._port, self._timeout
        )
        return self._server

    def __exit__(self, *args, **kwargs):
        from byteblowerll import byteblower
        instance = byteblower.ByteBlower.InstanceGet()
        try:
            instance.ServerRemove(self._server)
        except byteblower.ByteBlowerAPIException:
            pass
        self._server = None


class Frame(object):

    def __init__(self, frame_tree):
        self._tree = frame_tree

    @property
    def name(self):
        return self._tree.get('name')

    @name.setter
    def name(self, name):
        self._tree.set('name', name)

    def copy(self, name):
        parent = self._tree.getparent()

        new_tree = deepcopy(self._tree)
        new_frame = Frame(new_tree)
        parent.append(new_tree)

        new_frame.name = name

        return new_frame

    @property
    def udp_src_port(self):
        content = self._tree.get('bytesHexString')
        scapy_content = Ether(binascii.a2b_hex(content))
        return scapy_content[UDP].sport

    @udp_src_port.setter
    def udp_src_port(self, value):
        content = self._tree.get('bytesHexString')
        scapy_content = Ether(binascii.a2b_hex(content))
        scapy_content[UDP].sport = value
        self._tree.set(
            'bytesHexString', binascii.hexlify(bytes(scapy_content))
        )

    @property
    def udp_dst_port(self):
        content = self._tree.get('bytesHexString')
        scapy_content = Ether(binascii.a2b_hex(content))
        return scapy_content[UDP].dport

    @udp_dst_port.setter
    def udp_dst_port(self, value):
        content = self._tree.get('bytesHexString')
        scapy_content = Ether(binascii.a2b_hex(content))
        scapy_content[UDP].dport = value
        self._tree.set(
            'bytesHexString', binascii.hexlify(bytes(scapy_content))
        )

    @property
    def size(self):
        content = self._tree.get('bytesHexString')
        scapy_content = Ether(binascii.a2b_hex(content))
        return len(scapy_content)


class FlowTemplate(object):
    """Interface to a flow template configuration."""

    def __init__(self, flow_template_tree) -> None:
        self._tree = flow_template_tree

    @property
    def name(self):
        return self._tree.get('name')

    @property
    def frame_interval(self):
        return self._tree.get("frameInterval")

    @frame_interval.setter
    def frame_interval(self, new_value: Union[float, int]):
        """
        Set the new frame interval.

        .. :param new_value: Interval in nanoseconds

        .. note::
           The value will be truncated to the nearest integer value.
        """
        # ByteBlower GUI only accepts integer value (nanoseconds)
        self._tree.set("frameInterval", str(int(new_value)))


class Scenario(object):
    """Interface to a scenario configuration."""

    def __init__(self, scenario_tree) -> None:
        self._tree = scenario_tree

    @property
    def name(self):
        return self._tree.get('name')

    @property
    def duration(self) -> Optional[int]:
        max_scheduled_stop: int = None
        for measurements in self._tree.iterfind("measurements"):
            flow_stop_event = next(measurements.iterfind("flowStopEvent"))
            scheduled_stop: Optional[str] = flow_stop_event.get(
                "scheduledTime"
            )
            if scheduled_stop is not None:
                scheduled_stop = int(scheduled_stop)
                if max_scheduled_stop is None or scheduled_stop > max_scheduled_stop:
                    max_scheduled_stop = scheduled_stop
        return max_scheduled_stop

    @duration.setter
    def duration(self, new_value: Union[float, int]):
        """
        Set the new duration.

        .. :param new_value: Duration in nanoseconds

        .. note::
           The value will be truncated to the nearest integer value.
        """
        # ByteBlower GUI only accepts integer value (nanoseconds)
        new_scheduled_stop = int(new_value)
        for measurements in self._tree.iterfind("measurements"):
            flow_stop_event = next(measurements.iterfind("flowStopEvent"))
            scheduled_stop: Optional[str] = flow_stop_event.get(
                "scheduledTime"
            )
            if scheduled_stop is not None:
                flow_stop_event.set("scheduledTime", str(new_scheduled_stop))


class ByteBlowerGUIPort(object):
    """A port object."""

    def __init__(self, port_tree):
        self._tree = port_tree

    def _dock_to(
        self, server_address, physical_interface_id, byteblower_interface_id,
        server_type
    ):
        for portConfig in self._tree.iterfind('ByteBlowerGuiPortConfiguration'
                                              ):
            attributes = portConfig.attrib
            new_server_address = server_address or attributes[
                'physicalServerAddress']

            attributes['physicalInterfaceId'] = str(physical_interface_id)
            attributes['physicalPortId'] = str(byteblower_interface_id)
            attributes['physicalServerAddress'] = new_server_address
            attributes['physicalServerType'] = server_type

    def dock_to_interface(self, server_address, interface_name):
        """Docks a ByteBlower Port to a ByteBlower Interface

        :param server_address: The address of the ByteBlower server to dock the port to
        :type server_address: str
        :param interface_name: Name of the interface to dock the port to.  E.g. trunk-1-1
        :type interface_name: str
        """
        docking_parameters = _find_docking_parameters(
            server_address, interface_name
        )

        if docking_parameters is None:
            # something went wrong
            raise DockFailed("Unable to resolve dock parameters")

        physical_id, interface_id = docking_parameters
        self._dock_to(server_address, physical_id, interface_id, 'ByteBlower')

    def dock_to_wireless_endpoint(self, meetingpoint_address, device_uuid):
        """Docks a ByteBlower Port to a ByteBlower Interface

        :param meetingpoint_address: The address of the ByteBlower MeetingPoint to dock the port to
        :type meetingpoint_address: str
        :param device_uuid: UUID of the device to dock to.
        :type device_uuid: str
        """
        self._dock_to(meetingpoint_address, device_uuid, '-1', 'MeetingPoint')

    def set_mac(self, new_mac):
        if ':' not in new_mac:
            raise FormatError(
                "Unknown MAC Address Format, provide mac as 00:11:22:33:44:55"
            )

        mac_list = new_mac.split(':')

        for l2 in self._tree.iterfind('layer2Configuration'):
            for macaddress in l2.iterfind('MacAddress'):
                for i in range(6):
                    new_val = int(mac_list[i], 16)
                    if new_val > 127:
                        new_val = (256 - new_val) * -1

                    macaddress[i].text = str(new_val)

    @staticmethod
    def _set_address(obj, new_address):
        address_list = new_address.split('.')

        for i in range(4):
            new_val = int(address_list[i])
            if new_val > 127:
                new_val = (256 - new_val) * -1

            obj[i].text = str(new_val)

    def set_ip(self, ip):
        """ Sets the IPv4 address for a ByteBlower Port

        :param ip: The IP address for the ByteBlower Port in the form of "10.4.8.200"
        :type ip: str
        """
        for l3config in self._tree.iterfind("ipv4Configuration"):
            l3config.attrib['addressConfiguration'] = "Fixed"

            for ip_obj in l3config.iterfind("IpAddress"):
                self._set_address(ip_obj, ip)

    def set_netmask(self, netmask):
        """ Sets the IPv4 netmask for a ByteBlower Port

        :param netmask: The netmask for the ByteBlower Port in the form of "255.255.255.0"
        :type netmask: str
        """
        for l3config in self._tree.iterfind("ipv4Configuration"):
            l3config.attrib['addressConfiguration'] = "Fixed"

            for netmask_obj in l3config.iterfind("Netmask"):
                self._set_address(netmask_obj, netmask)

    def set_gateway(self, gateway):
        """ Sets the IPv4 gateway for a ByteBlower Port

        :param gateway: The gateway for the ByteBlower Port in the form of "10.4.8.1"
        :type gateway: str
        """
        for l3config in self._tree.iterfind("ipv4Configuration"):
            l3config.attrib['addressConfiguration'] = "Fixed"

            for gateway_obj in l3config.iterfind("DefaultGateway"):
                self._set_address(gateway_obj, gateway)


class ByteBlowerProjectFile(object):
    """Simple class representing a ByteBlower project file."""

    def __init__(self, filename):
        self._filename = filename
        self._tree = None

    def load(self):
        """ Reads the file from disk and parses it
        :raises: :class:`.ProjectParseError` when the project could not be parsed
        :raises: :class:`FileNotFoundException` when the project cannot be found
        """
        try:
            with open(self._filename, 'r') as f:
                self._tree = etree.parse(f)

                if self._tree is None:
                    raise ProjectParseError(f"Can't parse {self._filename!r}")
        except etree.ParseError as pe:
            raise ProjectParseError(f"Can't parse {self._filename!r}") from pe

    def save(self):
        self.save_as(self._filename)

    def save_as(self, new_filename):
        self._tree.write(new_filename)

    def get_port(self, name):
        return ByteBlowerGUIPort(self._find_port(name))

    def get_port_docking(self, port_name):
        """Gets the current port docking information
        :return: The current docking information (server_address, physical_interface_id, byteblower_interface_id)
        :rtype: tuple
        """
        port = self._find_port(port_name)

        for portConfig in port.iterfind('ByteBlowerGuiPortConfiguration'):
            attributes = portConfig.attrib

            return (
                attributes['physicalServerAddress'],
                attributes['physicalInterfaceId'], attributes['physicalPortId']
            )

        return None

    def _find_port(self, port_name):
        for port in self._tree.iterfind("ByteBlowerGuiPort"):
            if port.attrib['name'] == port_name:
                return port

        raise PortNotFound(
            "Could not find a port named '{}' in project '{}'".format(
                port_name, self._filename
            )
        )

    def list_port_names(self):
        ports = []
        for port in self._tree.iterfind("ByteBlowerGuiPort"):
            ports.append(port.attrib['name'])
        return ports

    def list_flow_names(self):
        flows = []
        for flow in self._tree.iterfind("Flow"):
            flows.append(flow.attrib['name'])
        return flows

    def _find_flow_template(self, name):
        for template in self._tree.iterfind("FlowTemplate"):
            if template.attrib['name'] == name:
                return template

        raise ElementNotFound(
            f"Could not find a flow template named '{name}'"
            f" in project '{self._filename}'"
        )

    def get_flow_template(self, name):
        return FlowTemplate(self._find_flow_template(name))

    def list_flow_template_names(self):
        flow_templates = []
        for flow in self._tree.iterfind("FlowTemplate"):
            flow_templates.append(flow.attrib['name'])
        return flow_templates

    def _find_scenario(self, name):
        for scenario in self._tree.iterfind("Scenario"):
            if scenario.attrib['name'] == name:
                return scenario

        raise ElementNotFound(
            f"Could not find a scenario named '{name}'"
            f" in project '{self._filename}'"
        )

    def get_scenario(self, name):
        return Scenario(self._find_scenario(name))

    def list_scenario_names(self):
        scenarios = []
        for scenario in self._tree.iterfind("Scenario"):
            scenarios.append(scenario.attrib['name'])
        return scenarios

    def list_frame_names(self):
        frames = []
        for frame in self._tree.iterfind('Frame'):
            frames.append(frame.attrib['name'])
        return frames

    def _find_frame(self, name):
        for frame in self._tree.iterfind('Frame'):
            if frame.get('name') == name:
                return frame
        raise FrameNotFound(
            "Could not find a port named '{}' in project '{}'".format(
                name, self._filename
            )
        )

    def get_frame(self, name):
        """Gets a frame with a specified name

        :param name: Name to search.
        :type name: str

        :raises: :class:`.FrameNotFound` when a frame cannot be found.

        :return: The Frame specified by the name param
        :rtype: :class:`.Frame`
        """
        return Frame(self._find_frame(name))

    def copy_frame(
        self, name, copies, increment_source_port, increment_destination_port
    ):
        frame = self.get_frame(name)

        for i in range(1, copies + 1):
            new_frame = frame.copy(name + "_" + str(i))
            if increment_source_port:
                new_frame.udp_src_port += i

            if increment_destination_port:
                new_frame.udp_dst_port += i

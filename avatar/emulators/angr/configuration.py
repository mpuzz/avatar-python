class BinaryFileConfiguration(Object):
    _binary = None
    section_maps = []

    def __init__(self, configuration, binary):
        self._binary = binary
        self.section_maps = [mapping in configuration._memory_map
                             if mapping['file'] == binary]

    def set_is_main(self):
        self._is_main = True

    def is_main(self):
        return self._is_main

class AngrConfiguration(Object):
    """
    This class defines the conventions for the configuration
    of the SimuvexEmulator objects.
    """

    binaries = []
    binary_file_conf = {}

    def __init__(self, configuration):
        """
        """
        assert("angr" in configuration)
        assert("machine_configuration" in configuration)

        angr_conf = configuration['angr']
        if "plugins" in angr_conf:
            plugins_conf = angr_conf['plugins']
            if "RemoteMemory" in plugins_conf:
                #retreiving the remote ranges
                if "ranges" in plugins_conf["RemoteMemory"] \
                    and configuration["RemoteMemory"]["ranges"]:
                    self.ranges = configuration["RemoteMemory"]["ranges"]
                
        machine_conf = configuration['machine_configuration']
        if 'architecture' in machine_conf:
            self._arch = machine_conf['architecture']

        if 'cpu_model' in 
            self._cpu_model = machine_conf['cpu_model']

        if 'entry_address' in machine_conf:
            self._entry_address = machine_conf['entry_address']

        if 'memory_map' in machine_conf:
            self._memory_map = machine_conf['memory_map']
            binaries = set([mapping['file'] for mapping in self._memory_map])
            binaries -= set([None])

        if 'main_binary' in machine_conf:
            self._main_binary = machine_conf['main_binary']

        self.binary_file_conf = {binary: BinaryFileConfiguration(self, binary)
                                 for binary in self.binaries}

        if 'devices' in machine_conf:
            self._arch = machine_conf['devices']



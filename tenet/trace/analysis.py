import bisect
from tenet.util.log import pmsg

#-----------------------------------------------------------------------------
# analysis.py -- Trace Analysis
#-----------------------------------------------------------------------------
#
#    This file should contain logic to further process, augment, optimize or
#    annotate Tenet traces when a binary analysis framework such as IDA /
#    Binary Ninja is available to a trace reader.
#
#    As of now (v0.2) the only added analysis we do is to try and map
#    ASLR'd trace addresses to executable opened in the database.
#
#    In the future, I imagine this file will be used to indexing events
#    such as function calls, returns, entry and exit to unmapped regions,
#    service pointer annotations, and much more.
#

class TraceAnalysis(object):
    """
    A high level, debugger-like interface for querying Tenet traces.
    """

    def __init__(self, trace, dctx, manual_slide=None): # Add manual_slide parameter
        self._dctx = dctx
        self._trace = trace
        self._remapped_regions = []
        self._unmapped_entry_points = []
        self.slide = manual_slide # Initialize with manual_slide (could be None)
        self._analyze(manual_slide=manual_slide) # Pass it to _analyze

    #-------------------------------------------------------------------------
    # Public
    #-------------------------------------------------------------------------

    def rebase_pointer(self, address):
        """
        Return a rebased version of the given address, if one exists.
        """
        for m1, m2 in self._remapped_regions:
            #print(f"m1 start: {m1[0]:08X} address: {address:08X} m1 end: {m1[1]:08X}")
            #print(f"m2 start: {m2[0]:08X} address: {address:08X} m2 end: {m2[1]:08X}")
            if m1[0] <= address <= m1[1]:
               return address + (m2[0] - m1[0])
            if m2[0] <= address <= m2[1]:
               return address - (m2[0] - m1[0])
        return address

    def get_prev_mapped_idx(self, idx):
        """
        Return the previous idx to fall within a mapped code region.
        """
        index = bisect.bisect_right(self._unmapped_entry_points, idx) - 1
        try:
            return self._unmapped_entry_points[index]
        except IndexError:
            return -1

    def unrebase_pointer(self, rebased_address):
        """
        Convert a rebased address (from disassembler) back to its original trace address.

        Args:
            rebased_address (int): The address based on the disassembler's imagebase.

        Returns:
            int or None: The original address in the trace space, or None if slide is unknown.
        """
        # Use logging module, assuming it's imported or available in the scope
        # import logging # Make sure logging is imported if not already
        # logger = logging.getLogger("Tenet.Trace.Analysis") # Get a logger instance
        
        if self.slide is None:
            print(f"Cannot unrebase pointer 0x{rebased_address:X}: ASLR slide is unknown (None).") # Assuming logger is defined
            # print(f"[Tenet Warning] Cannot unrebase pointer 0x{rebased_address:X}: ASLR slide is unknown (None).") # Using print if logger isn't set up
            return None
            
        # ASLR slide = disassembler_base - runtime_base
        # runtime_base = disassembler_base - slide
        # original_address = rebased_address - slide
        original_address = rebased_address - self.slide
        # logger.debug(f"Unrebased 0x{rebased_address:X} to 0x{original_address:X} (slide: {self.slide})")
        return original_address

    def unrebase_pointer(self, rebased_address):
       """
       Convert a rebased address (from disassembler) back to its original trace address.

       Args:
           rebased_address (int): The address based on the disassembler's imagebase.

       Returns:
           int or None: The original address in the trace space, or None if slide is unknown.
       """
       if self.slide is None:
           print(f"Cannot unrebase pointer 0x{rebased_address:X}: ASLR slide is unknown (None).")
           # Depending on strategy, you might return rebased_address or raise an error.
           # Returning None indicates the conversion couldn't be performed reliably.
           return None
           
       # ASLR slide is the difference: disassembler_base - runtime_base
       # So, runtime_base = disassembler_base - slide
       # Therefore, original_address = rebased_address - slide
       original_address = rebased_address - self.slide
       # logger.debug(f"Unrebased 0x{rebased_address:X} to 0x{original_address:X} (slide: {self.slide})") # Optional debug log
       return original_address

    #-------------------------------------------------------------------------
    # Analysis
    #-------------------------------------------------------------------------

    def _analyze(self, manual_slide=None): # Add manual_slide parameter
        """
        Analyze the trace against the binary loaded by the disassembler.
        """
        self._analyze_aslr(manual_slide=manual_slide) # Pass it to _analyze_aslr
        self._analyze_unmapped()

    def _analyze_aslr(self, manual_slide=None): # Add manual_slide parameter
        """
        Analyze trace execution to resolve ASLR mappings against the disassembler.
        """
        dctx = self._dctx
        if dctx is None:
            self.slide = None
            return False

        instruction_addresses = dctx.get_instruction_addresses()
        if not instruction_addresses:
            pmsg("[Tenet] No instruction addresses in current IDA database, skipping ASLR analysis.")
            self.slide = None
            return False

        # IDA was already rebased from the selected dump regs.json/reg.json.
        # Keep Tenet analysis in the same runtime address space instead of
        # guessing a second ASLR slide from trace instruction buckets.
        disas_low_address = instruction_addresses[0]
        disas_high_address = instruction_addresses[-1]
        m1 = [disas_low_address, disas_high_address]
        m2 = [disas_low_address, disas_high_address]

        self.slide = 0
        self._remapped_regions.append((m1, m2))
        return True

    def _analyze_unmapped(self):
        """
        Analyze trace execution to identify entry/exit to unmapped segments.
        """
        if self.slide is None:
            return

        # alias for readability and speed
        trace, ips = self._trace, self._trace.ip_addrs
        lower_mapped, upper_mapped = self._remapped_regions[0][1]

        #
        # for speed, pull out the 'compressed' ip indexes that matched mapped
        # (known) addresses within the disassembler context
        #

        mapped_ips = set()
        for i, address in enumerate(ips):
            if lower_mapped <= address <= upper_mapped:
                mapped_ips.add(i)

        last_good_idx = 0
        unmapped_entries = []

        # loop through each segment in the trace
        for seg in trace.segments:
            seg_ips = seg.ips
            seg_base = seg.base_idx

            # loop through each executed instruction in this segment
            for relative_idx in range(0, seg.length):
                compressed_ip = seg_ips[relative_idx]

                # the current instruction is in an unmapped region
                if compressed_ip not in mapped_ips:

                    # if we were in a known/mapped region previously, then save it
                    if last_good_idx:
                        unmapped_entries.append(last_good_idx)
                        last_good_idx = 0

                # if we are in a good / mapped region, update our current idx
                else:
                    last_good_idx = seg_base + relative_idx

        #print(f" - Unmapped Entry Points: {len(unmapped_entries)}")
        self._unmapped_entry_points = unmapped_entries

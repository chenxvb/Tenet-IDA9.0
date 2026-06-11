import os
import json
import logging
import traceback

from tenet.util.qt import *
from tenet.util.log import pmsg
from tenet.util.misc import is_plugin_dev

from tenet.stack import StackController
from tenet.memory import MemoryController
from tenet.registers import RegisterController
from tenet.breakpoints import BreakpointController
from tenet.ui.trace_view import TraceDock

from tenet.types import BreakpointType
from tenet.trace.arch import ArchAMD64, ArchX86, ArchAArch64 # Added ArchAArch64
from tenet.trace.reader import TraceReader
from tenet.integration.api import disassembler, DisassemblerContextAPI

logger = logging.getLogger("Tenet.Context")

#------------------------------------------------------------------------------
# context.py -- Plugin Database Context
#------------------------------------------------------------------------------
#
#    The purpose of this file is to house and manage the plugin's
#    disassembler database (eg, IDB/BNDB) specific runtime state.
#
#    At a high level, a unique 'instance' of the plugin runtime & subsystems
#    are initialized for each opened database in supported disassemblers. The
#    plugin context object acts a bit like the database specific plugin core.
# 
#    For example, it is possible for multiple databases to be open at once
#    in the Binary Ninja disassembler. Each opened database will have a
#    unique plugin context object created and used to manage state, UI,
#    threads/subsystems, and loaded plugin data for that database.
#
#    In IDA, this is less important as you can only have one database open
#    at any given time (... at least at the time of writing) but that does
#    not change how this context system works under the hood.
#

class TenetContext(object):
    """
    A per-database encapsulation of the plugin components / state.
    """

    def __init__(self, core, db):
        disassembler[self] = DisassemblerContextAPI(db)
        self.core = core
        self.db = db

        # select a trace arch based on the binary the disassmbler has loaded
        # NOTE: We assume the existence of an is_aarch64() method in the disassembler API.
        # This might need to be implemented in the integration layer later.
        # Determine architecture class using the new method in the integration API
        ArchClass = disassembler[self].get_tenet_arch_class()
        self.arch = ArchClass()
        logger.info(f"Selected Architecture: {ArchClass.__name__}")

        # this will hold the trace reader when a trace has been loaded
        self.reader = None

        # plugin widgets / components
        self.breakpoints = BreakpointController(self)
        self.trace = TraceDock(self)  # TODO: port this one to MVC pattern
        self.stack = StackController(self)
        self.memory = MemoryController(self)
        self.registers = RegisterController(self)

        # the directory to start the 'load trace file' dialog in
        self._last_directory = None
        
        # whether the plugin subsystems have been created / started
        self._started = False

        # NOTE/DEV: automatically open a test trace file when dev/testing
        if is_plugin_dev():
            self._auto_launch()

    def _auto_launch(self):
        """
        Automatically load a static trace file when the database has been opened.
        
        NOTE/DEV: this is just to make it easier to test / develop / debug the
        plugin when developing it and should not be called under normal use.
        """

        def test_load():
            import ida_loader
            trace_filepath = ida_loader.get_plugin_options("Tenet")
            focus_window()
            self.load_trace(trace_filepath)
            self.show_ui()

        def dev_launch():
            self._timer = QtCore.QTimer()
            self._timer.singleShot(500, test_load) # delay to let things settle

        self.core._ui_hooks.ready_to_run = dev_launch

    #-------------------------------------------------------------------------
    # Properties
    #-------------------------------------------------------------------------

    @property
    def palette(self):
        return self.core.palette
    
    #-------------------------------------------------------------------------
    # Setup / Teardown
    #-------------------------------------------------------------------------

    def start(self):
        """
        One-time initialization of the plugin subsystems.

        This will only be called when it is clear the user is attempting
        to use the plugin or its functionality (eg, they click load trace).
        """
        if self._started:
            return

        self.palette.warmup()
        self._started = True

    def terminate(self):
        """
        Spin down any plugin subsystems as the context is being deleted.

        This will be called when the database or disassembler is closing.
        """
        self.close_trace()
    
    def _find_latest_dump_and_rebase(self, trace_filepath):
        """
        Look for matching dump folders in the trace file's directory.
        If the latest dump folder contains reg.json with a 'base' field,
        automatically rebase IDA to that base address.

        Returns True if rebase was performed, False otherwise.
        """
        import ida_segment

        trace_dir = os.path.dirname(trace_filepath)
        if not trace_dir:
            trace_dir = "."

        # Find all dump directories matching the pattern (dump_*) that contain reg.json/regs.json
        dump_dirs = []
        try:
            for name in os.listdir(trace_dir):
                full_path = os.path.join(trace_dir, name)
                if not os.path.isdir(full_path):
                    continue
                if not name.startswith("dump_"):
                    continue
                # check for reg.json or regs.json
                reg_json = None
                for candidate in ("reg.json", "regs.json"):
                    candidate_path = os.path.join(full_path, candidate)
                    if os.path.isfile(candidate_path):
                        reg_json = candidate_path
                        break
                if reg_json:
                    mtime = os.path.getmtime(reg_json)
                    dump_dirs.append((mtime, full_path, reg_json))
        except OSError as e:
            logger.debug(f"Could not list dump directories in {trace_dir}: {e}")
            return False

        if not dump_dirs:
            logger.debug(f"No dump folders with reg.json found in {trace_dir}")
            return False

        # Sort by modification time (newest first), pick the latest
        dump_dirs.sort(key=lambda x: x[0], reverse=True)
        mtime, latest_dump_dir, reg_json_path = dump_dirs[0]

        # Parse reg.json
        try:
            with open(reg_json_path, 'r') as f:
                reg_data = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            pmsg(f"[Tenet] Failed to read reg.json from {latest_dump_dir}: {e}")
            return False

        if "base" not in reg_data:
            pmsg(f"[Tenet] reg.json in {latest_dump_dir} has no 'base' field, skipping auto-rebase")
            return False

        base = reg_data["base"]
        # Convert to int if it's a hex string
        if isinstance(base, str):
            try:
                base = int(base, 16) if base.startswith("0x") or base.startswith("0X") else int(base)
            except (ValueError, TypeError):
                pmsg(f"[Tenet] Invalid base value in reg.json: {base}")
                return False
        elif not isinstance(base, int):
            pmsg(f"[Tenet] Invalid base value type in reg.json: {type(base)}")
            return False

        # Perform IDA rebase
        try:
            # MSF_NOFIX = 0: do not fix up relocations
            ida_segment.rebase_program(base, 0)
            pmsg(f"[Tenet] Auto-rebased IDA to 0x{base:X} (from reg.json in {os.path.basename(latest_dump_dir)})")
            return True
        except Exception as e:
            pmsg(f"[Tenet] Failed to rebase IDA to 0x{base:X}: {e}")
            logger.exception("IDA rebase failed:")
            return False

    def trace_loaded(self):
        """
        Return True if a trace is loaded / active in this plugin context.
        """
        return bool(self.reader)

    def load_trace(self, filepath):
        """
        Load a trace from the given filepath.

        If there is a trace already loaded / in-use prior to calling this
        function, it will simply be replaced by the new trace.
        """

        #
        # create the trace reader. this will load the given trace file from
        # disk and wrap it with a number of useful APIs for navigating the
        # trace and querying information (memory, registers) from it at
        # chosen states of execution
        #

        self.reader = TraceReader(filepath, self.arch, disassembler[self])
        pmsg(f"Loaded trace {self.reader.trace.filepath}")
        pmsg(f"- {self.reader.trace.length:,} instructions...")

        #gmg commented the following check points
        # if self.reader.analysis.slide != None:
        #     pmsg(f"- {self.reader.analysis.slide:08X} ASLR slide...")
        # else:
        #     disassembler.warning("Failed to automatically detect ASLR base!\n\nSee console for more info...")
        #     pmsg(" +------------------------------------------------------")
        #     pmsg(" |- ERROR: Failed to detect ASLR base for this trace.")
        #     pmsg(" |       ---------------------------------------     ")
        #     pmsg(" +-+  You can 'try' rebasing the database to the correct ASLR base")
        #     pmsg("   |  if you know it, and reload the trace. Otherwise, it is possible")
        #     pmsg("   |  your trace is just... very small and Tenet was not confident")
        #     pmsg("   |  predicting an ASLR slide.")

        #
        # we only hook directly into the disassembler / UI / subsytems once
        # a trace is loaded. this ensures that our python handlers don't
        # introduce overhead on misc disassembler callbacks when the plugin
        # isn't even being used in the reversing session.
        #

        self.core.hook()

        #
        # attach the trace engine to the various plugin UI controllers, giving
        # them the necessary access to drive the underlying trace reader
        #

        self.breakpoints.reset()
        self.trace.attach_reader(self.reader)
        self.stack.attach_reader(self.reader)
        self.memory.attach_reader(self.reader)
        self.registers.attach_reader(self.reader)

        #
        # connect any high level signals from the new trace reader
        #

        self.reader.idx_changed(self._idx_changed)

    def close_trace(self):
        """
        Close the current trace if one is active.
        """
        if not self.reader:
            return

        #
        # unhook the disassembler, as there will be no active / loaded trace
        # after this routine completes
        #

        self.core.unhook()

        #
        # close UI elements and reset their model / controllers
        #

        self.trace.hide()
        self.trace.detach_reader()
        self.stack.hide()
        self.stack.detach_reader()
        self.memory.hide()
        self.memory.detach_reader()
        self.registers.hide()
        self.registers.detach_reader()

        # misc / final cleanup
        self.breakpoints.reset()
        #self.reader.close()

        self.reader = None

    def show_ui(self):
        """
        Integrate and arrange the plugin widgets into the disassembler UI.

        TODO: ehh, there really shouldn't be any disassembler-specific stuff
        outside of the disassembler integration files. it doesn't really
        matter much right now but this should be moved in the future.
        """
        import ida_kernwin
        self.registers.show(position=ida_kernwin.DP_RIGHT)

        #self.breakpoints.dockable.set_dock_position("CPU Registers", ida_kernwin.DP_BOTTOM)
        #self.breakpoints.dockable.show()

        #ida_kernwin.activate_widget(ida_kernwin.find_widget("Output window"), True)
        #ida_kernwin.set_dock_pos("Output window", None, ida_kernwin.DP_BOTTOM)
        #ida_kernwin.set_dock_pos("IPython Console", "Output", ida_kernwin.DP_INSIDE)

        #self.memory.dockable.set_dock_position("Output window", ida_kernwin.DP_TAB | ida_kernwin.DP_BEFORE)
        self.memory.show("Output window", ida_kernwin.DP_TAB | ida_kernwin.DP_BEFORE)

        #self.stack.dockable.set_dock_position("Memory View", ida_kernwin.DP_RIGHT)
        self.stack.show("Memory View", ida_kernwin.DP_RIGHT)

        mw = get_qmainwindow()
        mw.addToolBar(QtCore.Qt.RightToolBarArea, self.trace)
        self.trace.show()

        # trigger update check
        self.core.check_for_update()
    
    #-------------------------------------------------------------------------
    # Integrated UI Event Handlers
    #-------------------------------------------------------------------------

    def interactive_load_trace(self, reloading=False):
        """
        Handle UI actions for loading a trace file.
        """

        # prompt the user with a file dialog to select a trace of interest
        filenames = self._select_trace_file()
        if not filenames:
            return

        # TODO: ehh, only support loading one trace at a time right now
        assert len(filenames) == 1, "Please select only one trace file to load"
        disassembler.show_wait_box("Loading trace from disk...")
        filepath = filenames[0]

        #
        # auto-detect matching dump folders and rebase IDA if reg.json
        # in the latest dump folder contains a 'base' field
        #
        self._find_latest_dump_and_rebase(filepath)

        # attempt to load the user selected trace
        try:
            self.load_trace(filepath)
        except:
            pmsg("Failed to load trace...")
            pmsg(traceback.format_exc())
            disassembler.hide_wait_box()
            return
        disassembler.hide_wait_box()

        #
        # if we are 're-loading', we are loading over an existing trace, so
        # there should already be plugin UI elements visible and active.
        # 
        # do not attempt to show / re-position the UI elements as they may
        # have been moved by the user from their default positions into 
        # locations that they prefer
        #

        if reloading:
            return

        # show the plugin UI elements, and dock its windows as appropriate
        self.show_ui()
        
    def interactive_next_execution(self):
        """
        Handle UI actions for seeking to the next execution of the selected address.
        """
        address = disassembler[self].get_current_address()
        rebased_address = self.reader.rebase_pointer(address)
        result = self.reader.seek_to_next(rebased_address, BreakpointType.EXEC)

        # TODO: blink screen? make failure more visible...
        if not result:
            pmsg(f"Go to 0x{address:08x} failed, no future executions of address")

    def interactive_prev_execution(self):
        """
        Handle UI actions for seeking to the previous execution of the selected address.
        """
        address = disassembler[self].get_current_address()
        rebased_address = self.reader.rebase_pointer(address)
        result = self.reader.seek_to_prev(rebased_address, BreakpointType.EXEC)

        # TODO: blink screen? make failure more visible...
        if not result:
            pmsg(f"Go to 0x{address:08x} failed, no previous executions of address")

    def interactive_first_execution(self):
        """
        Handle UI actions for seeking to the first execution of the selected address.
        """
        address = disassembler[self].get_current_address()
        rebased_address = self.reader.rebase_pointer(address)
        result = self.reader.seek_to_first(rebased_address, BreakpointType.EXEC)

        # TODO: blink screen? make failure more visible...
        if not result:
            pmsg(f"Go to 0x{address:08x} failed, no executions of address")

    def interactive_final_execution(self):
        """
        Handle UI actions for seeking to the final execution of the selected address.
        """
        address = disassembler[self].get_current_address()
        rebased_address = self.reader.rebase_pointer(address)
        result = self.reader.seek_to_final(rebased_address, BreakpointType.EXEC)

        # TODO: blink screen? make failure more visible...
        if not result:
            pmsg(f"Go to 0x{address:08x} failed, no executions of address")

    def _idx_changed(self, idx):
        """
        Handle a trace reader event indicating that the current IDX has changed.
        """
        dctx = disassembler[self]
        bin_address = self.reader.rebased_ip

        if not dctx.is_mapped(bin_address):
            last_good_idx = self.reader.analysis.get_prev_mapped_idx(idx)
            if last_good_idx == -1:
                return
            last_good_trace_address = self.reader.get_ip(last_good_idx)
            bin_address = self.reader.rebase_pointer(last_good_trace_address)

        dctx.navigate(bin_address)
        disassembler.refresh_views()

    def _select_trace_file(self):
        """
        Prompt a file selection dialog, returning file selections.
        
        This will save & reuses the last known directory for subsequent calls.
        """

        if not self._last_directory:
            self._last_directory = disassembler[self].get_database_directory()

        # create & configure a Qt File Dialog for immediate use
        file_dialog = QtWidgets.QFileDialog(
            None,
            'Open trace file',
            self._last_directory,
            'All Files (*.*)'
        )
        file_dialog.setFileMode(QtWidgets.QFileDialog.ExistingFiles)

        # prompt the user with the file dialog, and await filename(s)
        filenames, _ = file_dialog.getOpenFileNames()

        #
        # remember the last directory we were in (parsed from a selected file)
        # for the next time the user comes to load trace files
        #

        if filenames:
            self._last_directory = os.path.dirname(filenames[0]) + os.sep

        # log the captured (selected) filenames from the dialog
        logger.debug("Captured filenames from file dialog:")
        for name in filenames:
            logger.debug(" - %s" % name)

        # return the captured filenames
        return filenames

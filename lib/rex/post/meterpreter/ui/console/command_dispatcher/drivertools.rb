# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Driver tools
#
###
class Console::CommandDispatcher::Drivertools

  Klass = Console::CommandDispatcher::Drivertools

  include Console::CommandDispatcher

  #
  # Initializes an instance of the drivertools command interaction.
  #
  def initialize(shell)
    super
  end

  #
  # List of supported commands.
  #
  def commands
    {
      "do_work"        => "Do work son",
      "tdl"            => "Do nothing except receive an error message"
  #		"dev_image"  => "Attempt to grab a frame from webcam",
  #		"dev_audio"  => "Attempt to record microphone audio",
  #    "screengrab" => "Attempt to grab screen shot from process's active desktop"
    }
  end

  def cmd_do_work()
    client.drivertools.drivertools_do_work()
    print_line("[*] Did work")

    return true
  end

  def cmd_tdl(*args)
    remotefilename = nil

    tdl_opts = Rex::Parser::Arguments.new(
      "-h" => [ false, "Help Banner" ],
      "-f" => [ true, "Filename of the driver on the remote system" ]
    )

    tdl_opts.parse(args) { | opt, idx, val |
      case opt 
      when "-h"
        print_line("Usage: tdl <options>")
        print_line(tdl_opts.usage)
      when "-f"
        remotefilename = val
      end
    }

    if remotefilename.nil?
      print_line("[!] You must specify the file name of the driver located on the remote system")
      return false
    end

    res = client.drivertools.drivertools_tdl_do_nothing()

    res.each { |e| 
      if e.type == 86869
        print_line("[+] #{e.value}")
        sleep 0.05
      end
    }

    return true
  end
  # def cmd_dev_audio(*args)
  #   maxrec = 60

  #   if (args.length < 1)
  #     print_line("Usage: dev_audio <rec_secs>\n")
  #     print_line("Record mic audio\n")
  #     return true
  #   end

  #   secs = args[0].to_i
  #   if secs  > 0 and secs <= maxrec
  #     milsecs = secs*1000
  #     print_line("[*] Recording #{milsecs} miliseconds.\n")
  #     client.espia.espia_audio_get_dev_audio(milsecs)
  #     print_line("[*] Done.")
  #   else
  #     print_line("[-] Error: Recording time 0 to 60 secs \n")
  #   end

  #   return true
  # end

  # #
  # # Grab a screenshot of the current interactive desktop.
  # #
  # def cmd_screengrab( *args )
  #   if( args[0] and args[0] == "-h" )
  #     print_line("Usage: screengrab <path.jpeg> [view in browser: true|false]\n")
  #     print_line("Grab a screenshot of the current interactive desktop.\n")
  #     return true
  #   end

  #   show = true
  #   show = false if (args[1] and args[1] =~ /^(f|n|0)/i)

  #   path = args[0] || Rex::Text.rand_text_alpha(8) + ".jpeg"

  #   data = client.espia.espia_image_get_dev_screen

  #   if( data )
  #     ::File.open( path, 'wb' ) do |fd|
  #       fd.write( data )
  #     end
  #     path = ::File.expand_path( path )
  #     print_line( "Screenshot saved to: #{path}" )
  #     Rex::Compat.open_file( path ) if show
  #   end

  #   return true
  # end

  #
  # Name for this dispatcher
  #
  def name
    "Drivertools"
  end

end

end
end
end
end


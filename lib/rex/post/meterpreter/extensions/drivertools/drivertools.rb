# -*- coding: binary -*-

require 'rex/post/meterpreter/extensions/drivertools/tlv'

module Rex
module Post
module Meterpreter
module Extensions
module Drivertools

###
#
# This Meterpreter extensions provides functionality
# related to driver installation, removal, etc on
# Windows based targets
#
###
class Drivertools < Extension


  def initialize(client)
    super(client, 'drivertools')

    client.register_extension_aliases(
      [
        {
          'name' => 'drivertools',
          'ext'  => self
        },
      ])
  end

  def drivertools_send_vuln()
    request = Packet.create_request('drivertools_send_vuln')
    response = client.send_request(request)

    return true
  end

  def drivertools_set_vuln_loc(rsecs)
    request = Packet.create_request('drivertools_set_vuln_loc')
    request.add_tlv(TLV_TYPE_DEV_RECTIME, rsecs)
    response = client.send_request(request)

    return true
  end

    def drivertools_do_work()
    request = Packet.create_request('drivertools_do_work')
    response = client.send_request(request)
    if !(response.result == 0)
      puts "[+] Test!"
    end
    return true
  end

  # def drivertools_image_get_dev_screen
  #   request  = Packet.create_request( 'drivertools_do_work' )
  #   response = client.send_request( request )
  #   if( response.result == 0 )
  #     return response.get_tlv_value( TLV_TYPE_DEV_SCREEN )
  #   end
  #   return nil
  # end

end

end; end; end; end; end

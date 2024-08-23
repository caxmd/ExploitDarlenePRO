require 'http'
require 'resolv'
require 'socket'
require 'net/http'
require 'nokogiri'
require 'mechanize'
require 'chunky_png'


# Prompt user for target domain
print "Enter target domain: "
target = gets.chomp

# Create a new instance of the Resolver object
resolver = Resolv::DNS.new

# Find all subdomains
subdomains = []
resolver.each_resource(target, Resolv::DNS::Resource::IN::NS) do |resource|
    subdomains << resource.name.to_s
end

# Print the subdomains
if subdomains.any?
    puts "Subdomains found:"
    puts subdomains
else
    puts "No subdomains found."
end


class XSSScanner
  def initialize(url)
    @url = url
    @agent = Mechanize.new
  end

  def check_for_xss
    page = @agent.get(@url)
    form = page.forms.first
    form.fields.each do |field|
      original_value = field.value
      field.value = "<script>alert('XSS')</script>"
      begin
        page = form.submit
        if page.body.include? "alert('XSS')"
          puts "XSS vulnerability found on #{@url} in #{field.name} field"
        end
      rescue Mechanize::ResponseCodeError => e
        puts "Error: #{e.response_code}"
      ensure
        field.value = original_value
      end
    end
  end
end

scanner = XSSScanner.new("https://xss-game.appspot.com/level1/frame")
scanner.check_for_xss


def scan(host, port)
  begin
    s = TCPSocket.new(host, port)
    puts " [+] Port #{port} is open"
    s.close
  rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH
    puts " [-] Port #{port} is closed"
  end
end

# usage
host = "127.0.0.1"
ports = (1..65535).to_a
ports.each { |port| scan(host, port) }


def dns_enum(domain)
  resolver = Resolv::DNS.new

  begin
    # Enumerate nameservers
    nameservers = resolver.getresources(domain, Resolv::DNS::Resource::IN::NS)
    puts "Nameservers for #{domain}:"
    nameservers.each do |ns|
      puts "  #{ns.name}"
    end

    # Enumerate MX records
    mx_records = resolver.getresources(domain, Resolv::DNS::Resource::IN::MX)
    puts "MX records for #{domain}:"
    mx_records.each do |mx|
      puts "  #{mx.exchange} (priority #{mx.preference})"
    end

    # Enumerate A records
    a_records = resolver.getresources(domain, Resolv::DNS::Resource::IN::A)
    puts "A records for #{domain}:"
    a_records.each do |a|
      puts "  #{a.address}"
    end

    # Enumerate CNAME records
    cname_records = resolver.getresources(domain, Resolv::DNS::Resource::IN::CNAME)
    puts "CNAME records for #{domain}:"
    cname_records.each do |cname|
      puts "  #{cname.name}"
    end

  rescue Resolv::ResolvError => e
    puts "Error resolving DNS records for #{domain}: #{e}"
  end
end

puts "Enter the domain to enumerate:"
domain = gets.chomp

dns_enum(domain)



chars = ('a'..'z').to_a + ('A'..'Z').to_a + ('0'..'9').to_a + ['!', '@', '#', '$', '%', '^', '&', '*']

puts "Enter the length of the password: "
length = gets.chomp.to_i

password = Array.new(length) { chars.sample }.join

puts "Password: #{password}"


def change_mac_address(interface, new_mac)
  # Bring the interface down
  system("ifconfig #{interface} down")

  # Change the MAC address
  system("ifconfig #{interface} hw ether #{new_mac}")

  # Bring the interface up
  system("ifconfig #{interface} up")
end

puts "Enter the network interface (e.g. eth0): "
interface = gets.chomp

puts "Enter the new MAC address (e.g. 00:11:22:33:44:55): "
new_mac = gets.chomp

change_mac_address(interface, new_mac)


def scan(url)
  # These are common SQL injection payloads
  payloads = ["' OR 1=1; --", "' OR '1'='1"]

  payloads.each do |payload|
    response = HTTP.get(url + payload)
    if response.code == 200
      puts " [*] Possible SQL Injection Vulnerability Found At #{url}"
      break
    end
  end
end

# Test the scanner with a vulnerable URL
scan("http://testphp.vulnweb.com/artists.php?artist=1")


def scan(url, file)
  uri = URI(url + file)
  response = Net::HTTP.get_response(uri)

  if response.code == "200"
    puts "   ✔️✔️ #{file} found at #{url} ✔️✔️"
  else
    puts " ✖️✖️ #{file} not found at #{url} ✖️✖️"
  end
end

# usage
puts " [*] Enter the website URL (e.g. http://example.com):"
url = gets.chomp
files = ["/index.html", "/secret_file.txt"]
files.each { |file| scan(url, file) }


def hide_message(input_image, output_image, message)
  # Open the input image
  image = ChunkyPNG::Image.from_file(input_image)

  # Convert the message to binary
  binary_message = message.unpack("B*").first

  # Check if the message is too long to fit in the image
  raise "Message too long to fit in the image" if binary_message.length > image.pixels.length * 3

  # Iterate through each pixel and hide the message in the least significant bits
  image.pixels.each_with_index do |pixel, index|
    next if binary_message.empty?

    # Get the next 8 bits from the message
    next_bits = binary_message[0...8]
    binary_message = binary_message[8..-1]

    # Hide the bits in the least significant bits of the red, green, and blue values
    red = (pixel >> 16) & 0xff
    green = (pixel >> 8) & 0xff
    blue = pixel & 0xff

    red = (red & 0xfc) | next_bits[0...2].to_i(2)
    green = (green & 0xfc) | next_bits[2...4].to_i(2)
    blue = (blue & 0xfc) | next_bits[4...6].to_i(2)

    # Update the pixel with the hidden message
    image[index % image.width, index / image.width] = ChunkyPNG::Color.rgb(red, green, blue)
  end

  # Save the output image
  image.save(output_image)
end

# Usage: ruby steganography.rb input.png output.png "secret message"
input_image, output_image, message = ARGV
hide_message(input_image, output_image, message)



host = ARGV[0]
port = 80
# keep this port on 80 because this is a http banner grabber and http works on port 80

s = TCPSocket.open(host,port)

s.puts("GET / HTTP/1.1\r\n\r\n")

while line = s.gets
  puts line.chop
end
s.close


print "Enter a search term: "
term = gets.chomp

# Perform a Google search for the search term
uri = URI("https://www.google.com/search?q=#{term}")
response = Net::HTTP.get_response(uri)

# Print the response status and header information
puts "Response status: #{response.code} #{response.message}"
response.each_header do |key, value|
  puts "#{key}: #{value}"
end

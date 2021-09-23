require "json"
require "yaml"

if ARGV.length != 1
  puts "Usage: #{__FILE__} <year>"
  exit 1
end

year = ARGV[0]

unless Dir.exist?(year)
  puts "No subfolder for #{year}"
  exit 1
end

glob = "#{year}/*/*.json"
cve_files = Dir[glob]

puts "Analyzing #{cve_files.count} files"

states = Hash.new(0)
cnas = Hash.new(0)

cve_files.first(100000).each do |cve_file|
  begin
    cve_json = JSON.parse(File.read(cve_file))
  rescue
    puts "Failed to read #{cve_file}"
    next
  end

  meta_data = cve_json["CVE_data_meta"]
  next unless meta_data

  state = meta_data["STATE"]
  states[state] += 1
  next unless state == "PUBLIC"

  cna_email = meta_data["ASSIGNER"]
  cnas[cna_email] += 1

end

sorted_cnas = cnas.sort_by { |_, v| -v }.map do |cna|
  cna << "%0.1f" % ((cna.last.to_f / states["PUBLIC"]) * 100.0) + "%"
  cna.reverse.join(" : ")
end

puts "CVEs by state:\n#{states.sort.to_yaml}\n\n"
puts "Public CVEs by CNA:\n#{sorted_cnas.first(25).to_yaml}\n\n"

# require "pry";binding.pry

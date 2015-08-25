#!/usr/bin/ruby
##
##Author: Shashank Mathur
##
#
require "rubygems"
require "json"
require "net/http"
require "uri"
require 'open-uri'
require 'nokogiri'
require 'thread'
require 'monitor'
require 'io/console'
require 'openssl'

#Function to Analyze URL
def analyze(url)

	#Preparing to call RESTapi and json results
	base_uri = "https://api.ssllabs.com/api/v2"
	fanalyzeuri = URI.parse("#{base_uri}/analyze?host=#{url}&startNew=on")
	analyzeuri = URI.parse("#{base_uri}/analyze?host=#{url}")
        fhttp = Net::HTTP.new(fanalyzeuri.host,fanalyzeuri.port)
        http = Net::HTTP.new(analyzeuri.host,analyzeuri.port)

	#Using SSL
	fhttp.use_ssl = true
	fhttp.verify_mode = OpenSSL::SSL::VERIFY_NONE
	http.use_ssl = true
	http.verify_mode = OpenSSL::SSL::VERIFY_NONE

	#Receiving JSON
	frequest = Net::HTTP::Get.new(fanalyzeuri.request_uri)
        fresponse = fhttp.request(frequest)
	request = Net::HTTP::Get.new(analyzeuri.request_uri)
	response = fhttp.request(request)

	#Parsing JSON
	result = JSON.parse(fresponse.body)

	#Waiting for endpoints to generate
	until result.has_key?("endpoints")
			response = fhttp.request(request)
			result = JSON.parse(response.body)
	       		sleep(2)
	end

	#Waiting for ipaddresses to populate
	result["endpoints"].each_index do |i|
		until result["endpoints"][i].has_key?("ipAddress")
			response = fhttp.request(request)
			result = JSON.parse(response.body)
			sleep(5)

		end

		#Check for status if ready
		until result["endpoints"][i]["statusMessage"] == "Ready"
			response = fhttp.request(request)
			result = JSON.parse(response.body)
			sleep(30)
		end
	end
	return result
end

#Function to get warnings
def getwarnings(hostn, ipadr)

			#Getting Warning lines from actual SSLlabs web page since this info is not available through api yet
			doc = Nokogiri::HTML(open("https://www.ssllabs.com/ssltest/analyze.html?d=#{hostn}&s=#{ipadr}&hideResults=on"))
			#Printing warnings messages
			#doc.xpath("//div[contains(@class,'warningBox')]").each { |node| puts node.text}
			doc.xpath("//div[contains(@class,'warningBox')]").each { |node| puts node}
end

# Function to fetch details for hosts from ssllabs
def fetchdtls(hname)
       joup=analyze(hname)
       puts "<table border=\"1\" style=\"border-spacing: 0px;float: left;margin: 8px; table-layout:fixed;font-family: monospace;\">"
       puts "<td colspan=\"3\" style=\"text-align: center; font-size: 25px; background-color: #f1c40f; color: #0c2c40;\"><a href=\"https://www.ssllabs.com/ssltest/analyze.html?d=#{hname}&hideResults=on\" target=\"_blank\">#{hname}</a></td>"
       puts "<tr><th style=\"background-color: #041317; color: #F2F2F2; font-size: 14px; font-family: sans-serif; padding: 6px 2px;\">IP</th><th style=\"background-color: #041317; color: #F2F2F2; font-size: 14px; font-family: sans-serif; padding: 6px 2px;\">Grade</th><th style=\"background-color: #041317; color: #F2F2F2; font-size: 14px; font-family: sans-serif; padding: 6px 2px;\">Warnings</th></tr>"

       joup["endpoints"].each_index do |i|
       puts "<tr>"
       puts "<td style=\"text-align: center; padding: 15px 8px; font-size:12px; background-color: #0c2c40; color: #f1c40f; font-weight: bold; word-wrap: break-word;\">" + joup['endpoints'][i]['ipAddress'] + "</td>"
       puts "<td style=\"text-align: center; padding: 15px 8px; font-size:38px; background-color: #0c2c40; color: #f1c40f; word-wrap: break-word;\">" + joup['endpoints'][i]['grade'] + "</td>"
		if joup["endpoints"][i]["hasWarnings"]
			puts "<td style=\"text-align: center; padding: 15px 8px; font-size:12px; background-color: #0c2c40; color: #f1c40f; word-wrap: break-word;\">"
			getwarnings(hname, joup['endpoints'][i]['ipAddress'])
		        puts "</td>"
		else
			puts "<td style=\"text-align: center; padding: 15px 8px; font-size:12px; background-color: #0c2c40; color: #f1c40f; word-wrap: break-word; max-width: 100px;\">We do not have any warnings</td>"

		end
       end
       puts "</tr>"
end

# Array containing hostnames to check. Add any hosts you want to check in the domainnames.txt file.
host = IO.readlines("domainnames.txt").map(&:chomp)

# Beginning HTML
	puts "<meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\" />"
	puts "<body bgcolor=\"#C9DCE1\">"
	puts "<style> .warningBox {border: 1px solid #f1c40f; padding: 5px; background: #0c2c40; margin-top: 10px; font-weight: bold; color: #f1c40f;} </style>"
	puts "<style>a:visited {color: #089994}</style>"
	puts "<style>a:link {color: #3282BB}</style>"
	puts "<style>table, th, td {width: 50%}</style>"
	puts "<style>footer {position: absolute; bottom:0;}</style>"

#Declaring thread related variables

thread_count = 5
threads = Array.new(thread_count)
work_queue = SizedQueue.new(thread_count)
threads.extend(MonitorMixin)
threads_available = threads.new_cond
sysexit = false

# Declaring array for storing results as well as the mutex
results = Array.new
results_mutex = Mutex.new

# Creating Consumer and Producer for thread management
consumer_thread = Thread.new do
	loop do
		break if sysexit && work_queue.length == 0
		                           found_index = nil
					   threads.synchronize do
						   threads_available.wait_while do
							      threads.select { |thread| thread.nil? || thread.status == false  || thread["finished"].nil? == false}.length == 0
							         end
					   found_index = threads.rindex { |thread| thread.nil? || thread.status == false || thread["finished"].nil? == false }
					   end
					   hostn = work_queue.pop
					   threads[found_index] = Thread.new(hostn) do
						   results_mutex.synchronize do
						   results <<
						   fetchdtls(hostn)
						   end
       Thread.current["finished"] = true
       threads.synchronize do
	       threads_available.signal
       end
						   
					   end
	end
end

# Getting hosts processed in threads
producer_thread = Thread.new do
	host.each do |hostn|
		work_queue << hostn
		threads.synchronize do
			threads_available.signal
		end
	end
	sysexit = true
end

# Joining
producer_thread.join
consumer_thread.join

threads.each do |thread|
	    thread.join unless thread.nil?
end

# Putting output
       puts results.compact
       puts "<footer>"
       puts "This page was generated at " + Time.now.strftime("%d/%m/%Y %H:%M")
       puts "</footer>"

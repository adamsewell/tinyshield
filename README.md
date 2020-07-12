# tinyShield
## About
tinyShield is a plugin for WordPress that utilizes real-time IP blocklists that are generated from multiple sources. Most importantly, each site that uses tinyShield contributes information (ie, failed login attempts, user enumeration, etc) back to tinyShield to crowd source the detection of new attackers. We consider that, crowd sourced security. For more information, please visit https://tinyshield.me

## How tinyShield Works
tinyShield works in three parts: a allowlist, a blocklist, and a permanent allowlist. Both the allowlist and blocklist are rotating - as a visitor hits your website their IP address is compared to our ever-evolving blocklist to see if they are known to be producing malicious traffic. If the visitor is determined to be a known malicious IP address, we add that to your blocklist. If not, we add it to your allowlist. An IP address on either of these two lists will be rotated off in 24 hours on the blocklist and 1 hour on the allowlist, and will be re-checked upon their next attempt to connect to the site after that time. The permanent allowlist is configurable by you as the site owner. These are IP addresses that you know to be good. Upon activation, we automatically add the IP address that you activate the plugin from to ensure you're not locked out of the site. The permanent allowlist is never automatically purged, but you can remove entries yourself.

## Crowd Sourced Security
tinyShield reports some data from your site in order to improve our community and premium feeds. For each site that uses tinyShield, even using the community feed, will contribute back to help the other users of tinyShield. Think of it like herd immunity.

## Gain Access
tinyShield is made up of two components - the WordPress plugin and our servers. The plugin will not function correctly without registering with tinyShield. There is no cost for the community version of our real time blocklist. You have the option to upgrade to our professional list and gain access to a more comprehensive blocklist.

## Privacy
While tinyShield collects information from your site, we only collect the offending IP address, failed user login attempts, and the site the attempt was made on (as you can see from examination of the code). These items are only logged to determine patterns. No information we collect will EVER be sold or given to third parties.

This section will always be up-to-date with all information that is reported back to tinyShield. Also, we encourage you to review our source code for accurate information.

## Pricing
Currently, there is no charge for the community version of this service. The premium feed, billed annually at $39 USD per year, will help support the project and also automatically give you access to a more comprehensive feed.

## Performance and Downtime
In our testing, we have noticed no performance issues while using the plugin. If for some reason our servers are unreachable, the plugin will fail open. This means that if our servers are down for any reason, your site will continue to work and utilize the local cached lists.

## Other web application firewalls
While tinyShield does not cause any known conflicts with other WordPress security plugins, and can work well alongside them as an extra layer of protection.  It takes a very targeted approach to just real time blocklists. There are however, some plugins that are known to cause tinyShield to not operate normally. They are listed below.

* wp-spamshield

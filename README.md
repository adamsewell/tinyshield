# tinyShield
## About
tinyShield is a plugin for WordPress that utilizes real-time IP blacklists that are generated from multiple sources. Most importantly, each site that uses tinyShield contributes information (ie, failed login attempts, user enumeration, etc) back to tinyShield to crowd source the detection of new attackers. We consider that, crowd sourced security. For more information, please visit https://tinyshield.me

## How tinyShield Works
tinyShield works in three parts, a whitelist, a blacklist, and a permanent whitelist. Both the whitelist and blacklist are rotating, as a visitor hits your website their IP address is compared to our ever evolving blacklist to see if they are known to be producing malicious traffic. If the visitor is determined to be a known malicious IP address, we add that to your blacklist. If not, we add it to your whitelist. An IP address on either of these two list will be rotated off in 24 hours, to be re-checked upon their next attempt to connect to the site. The permanent whitelist is up to you to populate. These are IP addresses that you know to be good. Upon activation, we automatically add the IP address that you activate the plugin from to ensure you're not locked out of the site. This list is never automatically purged but you can remove entries yourself.

## Gain Access
tinyShield is made up of two components - the WordPress plugin and our servers. The plugin will not function correctly without registering with our site. There is no cost for the community version of our real time blacklist. https://tinyshield.me/signup

## Privacy
While tinyShield collects information from your site, as you can see from the code we only collect the offending IP address, failed user login attempts, and the site the attempt was made on. These items are only logged to determine patterns. No information we collect will EVER be sold or given to third parties.

## Pricing
Currently, there is no charge for the community version of this service. The premium feed, billed annually at $2.50 USD per month, will not only help you support the project but also give you access to a more comprehensive feed automatically.

## Performance and Downtime
In our testing, we have noticed no performance issues while using the plugin. If for some reason our servers are unreachable, the plugin will fail open. This means that if our servers are down for any reason, your site will continue to work and utilize the local cached lists.

## Other web application firewalls
While tinyShield does not cause any known conflicts with other WordPress security plugins, and can work well alongside them as an extra layer of protection.  It takes a very targeted approach to just real time blacklists.

Asterisk module res_zonkey_mwi
====

This is Asterisk module is developed to provide better integration of MWI
in Zonkey VoIP platform. It registers with Asterisk core event system and
subscirbes for MWI events. When Asterisk fires MWI event, this module will
check OpenSIPS presense table for active watchers of message-summary event
and send PUBLISH to OpenSIPS node within existing SUBSCRIBE dialog.

Module is using realtime to connect to DB. When creating PUBLISH SIP packet
it uses Call-ID, To-tag and From-tag found for the subscription.



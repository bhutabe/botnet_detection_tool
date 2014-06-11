#!/usr/bin/perl


package MyApp::Plack::Middleware::BotDetector;
# ABSTRACT: Plack middleware to identify bots and spiders

use Modern::Perl;
use Plack::Request;
use Regexp::Assemble;

use parent 'Plack::Middleware';

my $bot_regex = make_bot_regex();
print "==========================================\n";
print "Detecting bot by using 'Plack::Middleware'\n";
print "==========================================\n";

sub call
{
    my ($self, $env) = @_;
    my $req          = Plack::Request->new( $env );
    my $user_agent   = $req->user_agent;

    if ($user_agent)
    {
        $env->{'BotDetector.looks-like-bot'} = 1 if $user_agent =~ qr/$bot_regex/;
    }

    return $self->app->( $env );
}

sub make_bot_regex
{
    my $ra = Regexp::Assemble->new;
    while (<DATA>)
    {
        chomp;
        $ra->add( '\b' . quotemeta( $_ ) . '\b' );
    }

    return $ra->re;
}
sub log_cohort_event
{
    my ($self, %event)  = @_;
    return if $self->request->env->{'BotDetector.looks-like-bot'};
    $event{usertoken} ||= $self->sessionid || 'unknownuser';

    push @{ $self->cohort_events }, \%event;
}
print "=============================\n";
print "finsished Scanning\n";
print "******************\n";
print "******************\n";
print "Now Detecting IRC based botnet\n";
print "Usage: perl irc.pl\n";


1;
__DATA__
Baiduspider
Googlebot
YandexBot
AdsBot-Google
AdsBot-Google-Mobile
bingbot
facebookexternalhit
libwww-perl
aiHitBot
Baiduspider+
aiHitBot
aiHitBot-BP
NetcraftSurveyAgent
Google-Site-Verification
W3C_Validator
ia_archiver
Nessus
UnwindFetchor
Butterfly
Netcraft Web Server Survey
Twitterbot
PaperLiBot
Add Catalog
1PasswordThumbs
MJ12bot
SmartLinksAddon
YahooCacheSystem
TweetmemeBot
CJNetworkQuality
YandexImages
StatusNet
Untiny
Feedfetcher-Google
DCPbot
AppEngine-Google



exit;
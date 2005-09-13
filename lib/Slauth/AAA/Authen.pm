# Slauth authentication

package Slauth::AAA::Authen;

use strict;
#use warnings FATAL => 'all', NONFATAL => 'redefine';

use Slauth::Config;
use Slauth::Config::Apache;
use Slauth::Storage::Session_DB;
use Slauth::Storage::User_DB;
use CGI::Cookie;
use CGI::Carp qw(fatalsToBrowser);
use Apache::Access ();
use Apache::RequestUtil ();

use Apache::Const -compile => qw(OK DECLINED HTTP_UNAUTHORIZED);

use Apache::Access();

sub debug { Slauth::Config::debug; }

sub handler {
	my $r = shift;
	my $auth_type = $r->auth_type;

	# check if Slauth is on in this directory
	Slauth::Config::Apache::isEnabled($r) or return Apache::DECLINED;

	# we can only do Slauth cookie or Basic authentication
	( $auth_type eq "Slauth" )
		or ( $auth_type eq "Basic" )
		or return Apache::DECLINED;
	debug and print STDERR "entering Slauth::AAA::Authen uri=".$r->uri."\n";

	# instantiate a Slauth configuration object
	my $config = Slauth::Config->new( $r );

	#
	# check user
	#

	# handle Basic HTTP authentication
	debug and print STDERR "Slauth::AAA::Authen: auth_type=$auth_type\n";
	if ( $auth_type eq "Basic" ) {
		my ($status, $password) = $r->get_basic_auth_pw;

		# was the data good?  check the password...
		if ( $status == Apache::OK ) {
			# authentication data received
			if ( Slauth::Storage::User_DB::check_pw(
				$r->user, $password, $config ))
			{
				# good password
				debug and print STDERR "Slauth::AAA::Authen: Basic password OK\n";
				return Apache::OK;
			} else {
				# bad password
				debug and print STDERR "Slauth::AAA::Authen: Basic password denied\n";
				$r->realm( $config->get( "realm" ));
				return Apache::HTTP_UNAUTHORIZED;
			}

		# was the data bad?  return the error
		# (DECLINED means no data so we fall through to check cookies
		} elsif ( $status != Apache::DECLINED ) {
			debug and print STDERR "Slauth::AAA::Authen: Basic password error $status\n";
			return $status;
		}
	}

	# handle Slauth cookie authentication
	my %cookies = CGI::Cookie->fetch($r);
	if ( defined $cookies{"slauth_session"}) {
		debug and print STDERR "Slauth::AAA::Authen: found cookie\n";
		my $value = $cookies{"slauth_session"}->value;
		debug and print STDERR "Slauth::AAA::Authen: value=$value\n";
		my $expires = $cookies{"slauth_session"}->expires;
		#if (( ! defined $expires ) or $expires < time ) {
		#	# we always use an expiration so this is bogus
		#	# if it doesn't have on if it's expired
		#	debug and print STDERR "Slauth::AAA::Authen: no expiration\n";
		#	return Apache::HTTP_UNAUTHORIZED;
		#}
		my $login;
		if ( $login = Slauth::Storage::Session_DB::check_cookie( $value, $config )) {
			debug and print STDERR "Slauth::AAA::Authen: OK login=$login\n";
			$r->user($login);
			return Apache::OK;
		}
	}
	debug and print STDERR "Slauth::AAA::Authen: failure\n";

	$r->note_basic_auth_failure;
	return Apache::HTTP_UNAUTHORIZED;
}

1;

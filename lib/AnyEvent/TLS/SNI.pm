package AnyEvent::TLS::SNI;
# ABSTRACT: adds Server Name Indication (SNI) support to AnyEvent::TLS client.

=head1 SYNOPSIS

use AnyEvent::HTTP;
use AnyEvent::TLS::SNI;

my $cv = AnyEvent->condvar;
$cv->begin;
AnyEvent::HTTP::http_get(
    'https://sni.velox.ch/',
    tls_ctx => {
        verify => 1,
        verify_peername => 'https',
        host_name => 'sni.velox.ch'
    },
    sub {
        printf "Body length = %d\n", length( shift );
        $cv->end;
    }
);
$cv->recv;

=cut

use strict;
use warnings;
no warnings 'redefine';
no strict 'refs';
use AnyEvent::TLS;
use Net::SSLeay;
use Carp qw( croak );

croak 'Client side SNI not supported for this openssl'
    if Net::SSLeay::OPENSSL_VERSION_NUMBER() < 0x01000000;

{
    my $old_ref = \&{ 'AnyEvent::TLS::new' };
    *{ 'AnyEvent::TLS::new' } = sub {
        my ( $class, %param ) = @_;

        my $self = $old_ref->( $class, %param );

        $self->{host_name} = $param{host_name}
            if exists $param{host_name};

        $self;
    };
}

{
    my $old_ref = \&{ 'AnyEvent::TLS::_get_session' };
    *{ 'AnyEvent::TLS::_get_session' } = sub($$;$$) {
        my ($self, $mode, $ref, $cn) = @_;

        my $session = $old_ref->( @_ );

        if ( $mode eq 'connect' ) {
            if ( $self->{host_name} ) {
                Net::SSLeay::set_tlsext_host_name( $session, $self->{host_name} );
            }
        }

        $session;
    };
}

1;

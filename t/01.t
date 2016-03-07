use AnyEvent::HTTP;
use AnyEvent::TLS::SNI;
use Test::More;
use Net::SSLeay;

if ( Net::SSLeay::OPENSSL_VERSION_NUMBER() < 0x01000000 ) {
    done_testing();
    exit;
}

my $cv = AnyEvent->condvar;

my $body_no_sni;
$cv->begin;
AnyEvent::HTTP::http_get(
    'https://sni.velox.ch/',
    tls_ctx => {
        verify => 1,
        verify_peername => 'https',
    },
    sub {
        $body_no_sni = shift;
        $cv->end;
    }
);

my $body_sni;
$cv->begin;
AnyEvent::HTTP::http_get(
    'https://sni.velox.ch/',
    tls_ctx => {
        verify => 1,
        verify_peername => 'https',
        host_name => 'sni.velox.ch'
    },
    sub {
        $body_sni = shift;
        $cv->end;
    }
);

$cv->recv;

ok !$body_no_sni, 'SNI off';
ok length( $body_sni ), 'SNI on';

done_testing();
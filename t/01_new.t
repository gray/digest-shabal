use strict;
use warnings;
use Test::More tests => 15;
use Digest::Shabal;

new_ok('Digest::Shabal' => [$_], "algorithm $_") for qw(224 256 384 512);

is(eval { Digest::Shabal->new },     undef, 'no algorithm specified');
is(eval { Digest::Shabal->new(10) }, undef, 'invalid algorithm specified');

can_ok('Digest::Shabal',
    qw(clone reset algorithm hashsize add digest hexdigest b64digest)
);

for my $alg (qw(224 256 384 512)) {
    my $d1 = Digest::Shabal->new($alg);
    $d1->add('foo bar')->reset;
    is($d1->hexdigest, Digest::Shabal->new($alg)->hexdigest, 'reset');

    $d1->add('foobar');
    my $d2 = $d1->clone;
    is($d1->hexdigest, $d2->hexdigest, "clone of $alg");
}

<?php
namespace Jsq\EncryptionStreams;

class EcbIvTest extends \PHPUnit_Framework_TestCase
{
    public function testShouldReportCipherMethodOfECB()
    {
        $this->assertSame('ECB', (new EcbIv)->getCipherMethod());
    }

    public function testShouldReturnEmptyStringForCurrentIv()
    {
        $iv = new EcbIv();
        $this->assertEmpty($iv->getCurrentIv());
        $iv->update(openssl_random_pseudo_bytes(128));
        $this->assertEmpty($iv->getCurrentIv());
    }

    public function testSeekShouldBeNoOp()
    {
        $iv = new EcbIv();
        $baseIv = $iv->getCurrentIv();
        $iv->update(openssl_random_pseudo_bytes(128));
        $this->assertSame($baseIv, $iv->getCurrentIv());
    }

    public function testShouldSupportArbitrarySeeking()
    {
        $this->assertTrue((new EcbIv)->supportsArbitrarySeeking());
    }
}

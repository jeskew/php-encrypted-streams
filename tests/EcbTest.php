<?php
namespace Jsq\EncryptionStreams;

use PHPUnit\Framework\TestCase;

class EcbTest extends TestCase
{
    public function testShouldReportCipherMethodOfECB()
    {
        $this->assertSame('aes-256-ecb', (new Ecb)->getOpenSslName());
    }

    public function testShouldReturnEmptyStringForCurrentIv()
    {
        $iv = new Ecb();
        $this->assertEmpty($iv->getCurrentIv());
        $iv->update(random_bytes(128));
        $this->assertEmpty($iv->getCurrentIv());
    }

    public function testSeekShouldBeNoOp()
    {
        $iv = new Ecb();
        $baseIv = $iv->getCurrentIv();
        $iv->update(random_bytes(128));
        $this->assertSame($baseIv, $iv->getCurrentIv());
    }

    public function testShouldReportThatPaddingIsRequired()
    {
        $this->assertTrue((new Ecb)->requiresPadding());
    }
}

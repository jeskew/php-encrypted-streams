<?php
namespace Jsq\EncryptionStreams;

/**
 * AES CTR encryption trait
 * @property int[] iv The hash initialization vector, stored as eight 16-bit words
 * @property int[] ctrOffset The counter offset to add to the initialization vector
 */
trait AesCtrTrait
{
    use AesTrait;

    /**
     * @param string $iv
     * @return int[]
     */
    private function extractIvParts($iv)
    {
        return array_map(function ($part) {
            return unpack('nnum', $part)['num'];
        }, str_split($iv, 2));
    }

    /**
     * @param int[] $baseIv
     * @param int[] $ctrOffset
     * @return string
     */
    private function calculateCurrentIv(array $baseIv, array $ctrOffset)
    {
        $iv = array_fill(0, 8, 0);
        $carry = 0;
        for ($i = 7; $i >= 0; $i--) {
            $sum = $ctrOffset[$i] + $baseIv[$i] + $carry;
            $carry = (int) ($sum / 65536);
            $iv[$i] = $sum % 65536;
        }

        return implode(array_map(function ($ivBlock) {
            return pack('n', $ivBlock);
        }, $iv));
    }

    /**
     * @param int $incrementBy
     */
    private function incrementOffset($incrementBy)
    {
        for ($i = 7; $i >= 0; $i--) {
            $incrementedBlock = $this->ctrOffset[$i] + $incrementBy;
            $incrementBy = (int) ($incrementedBlock / 65536);
            $this->ctrOffset[$i] = $incrementedBlock % 65536;
        }
    }
}
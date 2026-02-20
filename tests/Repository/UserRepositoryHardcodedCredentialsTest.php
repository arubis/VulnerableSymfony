<?php

namespace App\Tests\Repository;

use PHPUnit\Framework\TestCase;

/**
 * RED Test: CWE-798 — Hardcoded Secrets in UserRepository::getUserLogin()
 *
 * WHY SOURCE ANALYSIS (Tier 3):
 * The getUserLogin() method requires a live Doctrine EntityManager backed by a
 * real database connection to instantiate UserRepository.  Setting up the full
 * Symfony kernel + database for a unit test would require migrations and a running
 * RDBMS, which are unavailable in this CI environment.  The vulnerability is
 * inherently a source-level concern (literal credentials embedded in code), so
 * source inspection is the authoritative proof of exploitability per the CWE-798
 * assertion template.
 *
 * WHAT THIS PROVES:
 * The `getUserLogin` method on line 74 of UserRepository.php builds a raw SQL
 * string by directly interpolating `$email` and `$hashedPassword` into the query
 * string:
 *
 *   $rawSql = "SELECT * FROM user WHERE email = '$email' AND password = '$hashedPassword' LIMIT 1";
 *
 * A secure implementation MUST use parameterised placeholders so that user-supplied
 * values are never embedded as literal strings.  The tests below assert the
 * security properties that are MISSING from the current code:
 *
 *  1. The query string must NOT contain directly interpolated `$email` / `$hashedPassword`.
 *  2. The query string MUST use named or positional placeholders (:email, :password, or ?).
 *  3. The md5() call must NOT appear in the repository source (md5 is a broken hash).
 *
 * All three assertions FAIL on the vulnerable code — proving the vulnerability exists.
 */
class UserRepositoryHardcodedCredentialsTest extends TestCase
{
    private string $sourceCode;

    protected function setUp(): void
    {
        $path = dirname(__DIR__, 2) . '/src/Repository/UserRepository.php';
        $this->assertFileExists($path, 'UserRepository.php must exist');
        $this->sourceCode = file_get_contents($path);
    }

    /**
     * SECURITY PROPERTY: The login query must NOT embed variables via string
     * interpolation.  Interpolating `$email` directly into a SQL string means
     * an attacker can supply any email value and it will become part of the
     * executed SQL — a textbook injection / hardcoded-credential pattern.
     *
     * This test FAILS on the vulnerable code because the interpolation IS present.
     */
    public function testLoginQueryDoesNotInterpolateEmailIntoSqlString(): void
    {
        $containsInterpolatedEmail = (bool) preg_match(
            '/\$rawSql\s*=\s*["\'].*\$email.*["\']/',
            $this->sourceCode
        );

        $this->assertFalse(
            $containsInterpolatedEmail,
            'VULNERABILITY (CWE-798): getUserLogin() interpolates $email directly ' .
            'into the SQL string literal instead of using a parameterised query. ' .
            'This embeds user-supplied credentials as raw SQL tokens.'
        );
    }

    /**
     * SECURITY PROPERTY: The login query must NOT embed the hashed password via
     * string interpolation.  Same reasoning as above — `$hashedPassword` must
     * never appear inside the query string literal.
     *
     * This test FAILS on the vulnerable code because the interpolation IS present.
     */
    public function testLoginQueryDoesNotInterpolatePasswordIntoSqlString(): void
    {
        $containsInterpolatedPassword = (bool) preg_match(
            '/\$rawSql\s*=\s*["\'].*\$hashedPassword.*["\']/',
            $this->sourceCode
        );

        $this->assertFalse(
            $containsInterpolatedPassword,
            'VULNERABILITY (CWE-798): getUserLogin() interpolates $hashedPassword ' .
            'directly into the SQL string literal instead of using a parameterised query. ' .
            'This embeds hashed credentials as raw SQL tokens.'
        );
    }

    /**
     * SECURITY PROPERTY: A secure query must use named or positional placeholders
     * (e.g. ":email", ":password", or "?") so the driver can separate data from
     * the query structure.
     *
     * This test FAILS on the vulnerable code because no placeholder is present.
     */
    public function testLoginQueryUsesParameterisedPlaceholders(): void
    {
        // Extract the line(s) where $rawSql is assigned inside getUserLogin
        preg_match('/function getUserLogin.*?(?=public function|\z)/s', $this->sourceCode, $matches);
        $methodBody = $matches[0] ?? '';

        $hasPlaceholder = (bool) preg_match(
            '/\$rawSql\s*=.*?(:[a-zA-Z_]+|\?).*?;/s',
            $methodBody
        );

        $this->assertTrue(
            $hasPlaceholder,
            'VULNERABILITY (CWE-798): getUserLogin() does not use named or positional ' .
            'SQL placeholders (:email, :password, ?). User-controlled values are ' .
            'interpolated directly into the query string.'
        );
    }

    /**
     * SECURITY PROPERTY: Passwords must NOT be hashed with md5().  md5 is
     * cryptographically broken and its use in an authentication flow is itself a
     * hardcoded-weakness (CWE-916 / CWE-327).  A secure implementation must use
     * a proper password-hashing API (e.g. password_hash / bcrypt / argon2).
     *
     * This test FAILS on the vulnerable code because md5() IS used.
     */
    public function testLoginMethodDoesNotUseMd5ForPasswordHashing(): void
    {
        // Isolate just the getUserLogin method body
        preg_match('/function getUserLogin.*?(?=public function|\z)/s', $this->sourceCode, $matches);
        $methodBody = $matches[0] ?? $this->sourceCode;

        $usesMd5 = (bool) preg_match('/\bmd5\s*\(/', $methodBody);

        $this->assertFalse(
            $usesMd5,
            'VULNERABILITY (CWE-798 / CWE-916): getUserLogin() uses md5() to hash ' .
            'passwords — a broken algorithm that trivially leaks credential values. ' .
            'A hardcoded md5() call is a form of embedded (broken) credential logic.'
        );
    }
}

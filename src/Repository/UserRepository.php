<?php

namespace App\Repository;

use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\PasswordUpgraderInterface;
use function PHPUnit\Framework\returnArgument;

/**
 * @extends ServiceEntityRepository<User>
 *
 * @method User|null find($id, $lockMode = null, $lockVersion = null)
 * @method User|null findOneBy(array $criteria, array $orderBy = null)
 * @method User[]    findAll()
 * @method User[]    findBy(array $criteria, array $orderBy = null, $limit = null, $offset = null)
 */
class UserRepository extends ServiceEntityRepository implements PasswordUpgraderInterface
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, User::class);
    }

    public function save(User $entity, bool $flush = false): void
    {
        $this->getEntityManager()->persist($entity);

        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }

    public function remove(User $entity, bool $flush = false): void
    {
        $this->getEntityManager()->remove($entity);

        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }

    public function total(): int
    {
        return $this->createQueryBuilder("u")
            ->select("COUNT(u.id)")
            ->getQuery()
            ->getSingleScalarResult();
    }

    /**
     * Used to upgrade (rehash) the user's password automatically over time.
     */
    public function upgradePassword(PasswordAuthenticatedUserInterface $user, string $newHashedPassword): void
    {
        if (!$user instanceof User) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', \get_class($user)));
        }

        $user->setPassword($newHashedPassword);

        $this->save($user, true);
    }

    /**
     * Secure user login using parameterized queries and proper password verification
     */
    public function getUserLogin(string $email, string $password): false|array
    {
        // Use parameterized query to prevent SQL injection
        $rawSql = "SELECT * FROM user WHERE email = :email LIMIT 1";
        $conn = $this->getEntityManager()->getConnection();
        $stmt = $conn->prepare($rawSql);
        $result = $stmt->executeQuery(['email' => $email])->fetchAssociative();

        // Verify password using password_verify() instead of MD5
        // Note: This assumes passwords are stored with password_hash()
        // If migrating from MD5, a password migration strategy is needed
        if ($result && isset($result['password']) && password_verify($password, $result['password'])) {
            return $result;
        }

        return false;
    }
}

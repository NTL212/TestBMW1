package vn.iotstar.JPAConfig;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Persistence;

public class JpaConfig {
	public static EntityManager getEntityManager() {

		EntityManagerFactory factory = Persistence.createEntityManagerFactory("JPAServletSQL");

		return factory.createEntityManager();

		}
}

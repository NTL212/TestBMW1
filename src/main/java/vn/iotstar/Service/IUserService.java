package vn.iotstar.Service;

import java.util.List;

import vn.iotstar.Entity.User;

public interface IUserService {
	void insert(User user);

	void update(User user);
	
	void delete(int id) throws Exception;

	User get(String name);

	User get(int id);
	
	List<User> findAll();
	User checkLogin(String username,String password);
	User checkRegister(String username);
	User checkEmail(String email);
	int RegisterUser (User user);
}

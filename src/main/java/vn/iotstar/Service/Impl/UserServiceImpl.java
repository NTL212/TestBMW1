package vn.iotstar.Service.Impl;

import java.util.List;

import vn.iotstar.Dao.IUserDao;
import vn.iotstar.Dao.Impl.UserDaoImpl;
import vn.iotstar.Entity.User;
import vn.iotstar.Service.IUserService;

public class UserServiceImpl implements IUserService{
	IUserDao userdao = new UserDaoImpl();
	@Override
	public void insert(User user) {
		userdao.insert(user);
	}

	@Override
	public void update(User user) {
		userdao.update(user);
		
	}

	@Override
	public void delete(int id) throws Exception {
		userdao.delete(id);
		
	}

	@Override
	public User get(String name) {
		return userdao.get(name);
	}

	@Override
	public User get(int id) {
		return userdao.get(id);
	}

	@Override
	public List<User> findAll() {
		return userdao.findAll();
	}

	@Override
	public User checkLogin(String username,String password) {
		return userdao.checkLogin(username,password);
	}

	@Override
	public int RegisterUser(User user) {
		return userdao.RegisterUser(user);
	}

	@Override
	public User checkEmail(String email) {
		return userdao.checkEmail(email);
	}

	@Override
	public User checkRegister(String username) {
		return userdao.checkRegister(username);
	}

}

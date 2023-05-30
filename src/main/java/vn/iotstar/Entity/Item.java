package vn.iotstar.Entity;

public class Item {
	
	private String id;
	private Product product;
	private int qty;
	private double price;
	
	
	public Item() {
		super();
	}

	public Item(String id, Product product, int qty, double price) {
		super();
		this.id = id;
		this.product = product;
		this.qty = qty;
		this.price = price;
	}
	
	public String getId() {
		return id;
	}
	public void setId(String id) {
		this.id = id;
	}
	public Product getProduct() {
		return product;
	}
	public void setProduct(Product product) {
		this.product = product;
	}
	public int getQty() {
		return qty;
	}
	public void setQty(int qty) {
		this.qty = qty;
	}
	public double getPrice() {
		return price;
	}
	public void setPrice(double price) {
		this.price = price;
	}
}

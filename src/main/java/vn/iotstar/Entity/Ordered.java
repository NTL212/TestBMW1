package vn.iotstar.Entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.NamedQuery;
import javax.persistence.Table;

@Entity

@Table(name="ordered")
@NamedQuery(name="Ordered.findAll", query="SELECT o FROM Ordered o")
public class Ordered implements Serializable{
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name="id")
	private int id;
	
	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "product_id")
	private Product product_id;
	
	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "orderitem_id")
	private OrderItem orderitem_id;
	
	public Ordered(int id, Product product_id, OrderItem orderitem_id, int qty) {
		super();
		this.id = id;
		this.product_id = product_id;
		this.orderitem_id = orderitem_id;
		this.qty = qty;
	}

	@Column(name="qty")
	private int qty;
	public Ordered() {
		super();
	}

	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

	public Product getProduct_id() {
		return product_id;
	}

	public void setProduct_id(Product product_id) {
		this.product_id = product_id;
	}

	public OrderItem getOrderitem_id() {
		return orderitem_id;
	}

	public void setOrderitem_id(OrderItem orderitem_id) {
		this.orderitem_id = orderitem_id;
	}

	public int getQty() {
		return qty;
	}

	public void setQty(int qty) {
		this.qty = qty;
	}
	
	
}

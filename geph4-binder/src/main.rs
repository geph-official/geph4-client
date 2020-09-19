mod bindercore;
fn main() {
    let mut binder_core = bindercore::BinderCore::new_default();
    println!(
        "user info of LisaWei is {:?}",
        binder_core.get_user_info("LisaWei").unwrap()
    );
    dbg!(binder_core.verify_password("dorbie", "fc9dfc3d").unwrap());
    dbg!(binder_core.change_password("thisbefruit", "honya", "labooyah"));
}

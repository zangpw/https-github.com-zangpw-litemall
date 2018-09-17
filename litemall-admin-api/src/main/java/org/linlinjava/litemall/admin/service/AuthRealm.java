package org.linlinjava.litemall.admin.service;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.linlinjava.litemall.db.dao.LitemallAdminMapper;
import org.linlinjava.litemall.db.domain.LitemallAdmin;
import org.linlinjava.litemall.db.domain.LitemallAdminExample;

import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.List;

public class AuthRealm extends AuthorizingRealm {

    @Resource
    private LitemallAdminMapper adminMapper;
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        LitemallAdmin litemallAdmin=(LitemallAdmin) principalCollection.fromRealm(this.getClass().getName()).iterator().next();//获取session中的用户
        List<String> permissions=new ArrayList();

        return null;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        //获取用户的输入的账号.
        String username = (String) authenticationToken.getPrincipal();
        LitemallAdminExample example = new LitemallAdminExample();
        example.or().andUsernameEqualTo(username).andDeletedEqualTo(false);
        LitemallAdmin litemallAdmin = adminMapper.selectOneByExample(example);
        return new SimpleAuthenticationInfo(litemallAdmin, litemallAdmin.getPassword(),this.getClass().getName());//放入shiro.调用CredentialsMatcher检验密码
    }
}

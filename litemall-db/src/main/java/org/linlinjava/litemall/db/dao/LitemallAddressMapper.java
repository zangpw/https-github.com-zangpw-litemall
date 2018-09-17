package org.linlinjava.litemall.db.dao;

import java.util.List;
import org.apache.ibatis.annotations.Param;
import org.linlinjava.litemall.db.domain.LitemallAddress;
import org.linlinjava.litemall.db.domain.LitemallAddressExample;

public interface LitemallAddressMapper {
    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table litemall_address
     *
     * @mbg.generated
     */
    long countByExample(LitemallAddressExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table litemall_address
     *
     * @mbg.generated
     * @project https://github.com/itfsw/mybatis-generator-plugin
     */
    int deleteWithVersionByExample(@Param("version") Integer version, @Param("example") LitemallAddressExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table litemall_address
     *
     * @mbg.generated
     */
    int deleteByExample(LitemallAddressExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table litemall_address
     *
     * @mbg.generated
     * @project https://github.com/itfsw/mybatis-generator-plugin
     */
    int deleteWithVersionByPrimaryKey(@Param("version") Integer version, @Param("key") Integer key);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table litemall_address
     *
     * @mbg.generated
     */
    int deleteByPrimaryKey(Integer id);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table litemall_address
     *
     * @mbg.generated
     */
    int insert(LitemallAddress record);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table litemall_address
     *
     * @mbg.generated
     */
    int insertSelective(LitemallAddress record);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table litemall_address
     *
     * @mbg.generated
     * @project https://github.com/itfsw/mybatis-generator-plugin
     */
    LitemallAddress selectOneByExample(LitemallAddressExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table litemall_address
     *
     * @mbg.generated
     * @project https://github.com/itfsw/mybatis-generator-plugin
     */
    LitemallAddress selectOneByExampleSelective(@Param("example") LitemallAddressExample example, @Param("selective") LitemallAddress.Column ... selective);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table litemall_address
     *
     * @mbg.generated
     * @project https://github.com/itfsw/mybatis-generator-plugin
     */
    List<LitemallAddress> selectByExampleSelective(@Param("example") LitemallAddressExample example, @Param("selective") LitemallAddress.Column ... selective);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table litemall_address
     *
     * @mbg.generated
     */
    List<LitemallAddress> selectByExample(LitemallAddressExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table litemall_address
     *
     * @mbg.generated
     * @project https://github.com/itfsw/mybatis-generator-plugin
     */
    LitemallAddress selectByPrimaryKeySelective(@Param("id") Integer id, @Param("selective") LitemallAddress.Column ... selective);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table litemall_address
     *
     * @mbg.generated
     */
    LitemallAddress selectByPrimaryKey(Integer id);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table litemall_address
     *
     * @mbg.generated
     * @project https://github.com/itfsw/mybatis-generator-plugin
     */
    LitemallAddress selectByPrimaryKeyWithLogicalDelete(@Param("id") Integer id, @Param("andLogicalDeleted") boolean andLogicalDeleted);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table litemall_address
     *
     * @mbg.generated
     * @project https://github.com/itfsw/mybatis-generator-plugin
     */
    int updateWithVersionByExample(@Param("version") Integer version, @Param("record") LitemallAddress record, @Param("example") LitemallAddressExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table litemall_address
     *
     * @mbg.generated
     * @project https://github.com/itfsw/mybatis-generator-plugin
     */
    int updateWithVersionByExampleSelective(@Param("version") Integer version, @Param("record") LitemallAddress record, @Param("example") LitemallAddressExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table litemall_address
     *
     * @mbg.generated
     */
    int updateByExampleSelective(@Param("record") LitemallAddress record, @Param("example") LitemallAddressExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table litemall_address
     *
     * @mbg.generated
     */
    int updateByExample(@Param("record") LitemallAddress record, @Param("example") LitemallAddressExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table litemall_address
     *
     * @mbg.generated
     * @project https://github.com/itfsw/mybatis-generator-plugin
     */
    int updateWithVersionByPrimaryKey(@Param("version") Integer version, @Param("record") LitemallAddress record);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table litemall_address
     *
     * @mbg.generated
     * @project https://github.com/itfsw/mybatis-generator-plugin
     */
    int updateWithVersionByPrimaryKeySelective(@Param("version") Integer version, @Param("record") LitemallAddress record);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table litemall_address
     *
     * @mbg.generated
     */
    int updateByPrimaryKeySelective(LitemallAddress record);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table litemall_address
     *
     * @mbg.generated
     */
    int updateByPrimaryKey(LitemallAddress record);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table litemall_address
     *
     * @mbg.generated
     * @project https://github.com/itfsw/mybatis-generator-plugin
     */
    int logicalDeleteByExample(@Param("example") LitemallAddressExample example);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table litemall_address
     *
     * @mbg.generated
     * @project https://github.com/itfsw/mybatis-generator-plugin
     */
    int logicalDeleteByPrimaryKey(Integer id);
}
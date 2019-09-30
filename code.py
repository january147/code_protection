#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Date: Sat Sep 28 17:13:49 2019
# Author: January

import numpy as np
import math
# give echa variables an index starting from 1
# the table used in computation is as follows
#---------------------------------------------------------------------
# basic_var_index | var1_coefficient | var2_coefficient | ... | const 
# basic_var_index | var1_coefficient | var2_coefficient | ... | const
# ...
#        w        | var1_coefficient | var2_coefficient | ... | const
#---------------------------------------------------------------------
a = np.array(
    [[3, 1, -1, 0, 0, -1],
     [4, -2, -1, 0, 0, 18],
     [0,  4,  5, 0, 0,  0]]
     ,dtype=float
)

def findMaxW(a):
    # 计算变量个数（包括基本和非基本变量）
    var_num = len(a[0]) - 2
    equation_num = len(a)

    # 迭代求解
    while True:
        w_last = a[-1][-1]
        not_change_count = 0
        # 寻找使得w增长最快的非基本变量
        # 获取需要求最大值的等式
        w_expression = a[-1]
        w_coefficient_max_var = 0
        no_basic_var = 0
        for var_index in range(1, var_num + 1):
            if w_expression[var_index] > w_coefficient_max_var:
                no_basic_var = var_index
                w_coefficient_max_var = w_expression[var_index]

        # 没有变量可以选取使得w变大了，返回求解结果
        if w_coefficient_max_var <= 0:
            return a[-1][-1]
        
        # 寻找对该变量增长约束最严格的约束等式和对应的基本变量
        restrain_equations = a[0:-1]
        basic_var = 0
        equation_index = -1
        const_var_ratio_max = -math.inf
        for i in range(len(restrain_equations)):
            const = restrain_equations[i][-2]
            no_basic_var_coefficient = restrain_equations[i][no_basic_var]
            # 如果变量的系数大于等于0则表示其增大不受此等式约束
            if no_basic_var_coefficient >= 0:
                continue
            const_var_ratio = const / no_basic_var_coefficient
            if const_var_ratio > const_var_ratio_max:
                const_var_ratio_max = const_var_ratio
                basic_var = int(restrain_equations[i][0])
                equation_index = i

        # 搜索结果为所有等式都没有约束该变量的最大值，所以求解结果为无限大
        if equation_index == -1:
            return math.inf
        
        # 将该基本变量和非基本变量身份对换，更新所有等式
        # 首先调整上边选定的等式，我们称其为等式equation_index，把上边选定的非基本变量和基本变量互换
        no_basic_var_coefficient_reduce = -a[equation_index][no_basic_var]
        # 之前的基本变量换到非基本变量位置，其系数为-1
        a[equation_index][basic_var] = -1
        # 之前非基本变量的系数置为0
        a[equation_index][no_basic_var] = 0
        # 将之前的非基本变量放到基本变量的位置
        a[equation_index][0] = no_basic_var
        # 调整目前所有非基本变量系数
        for i in range(1, var_num + 2):
            a[equation_index][i] /= no_basic_var_coefficient_reduce

        # 根据更改后的等式对其他等式进行调整        
        for i in range(equation_num):
            old_no_basic_var_coefficient = a[i][no_basic_var]
            # 如果等式中之前选定的非基本变量系数不为0才需要调整
            if old_no_basic_var_coefficient != 0:
                # 将等式equation_index带入
                for var_index in range(1, var_num + 2):
                    coefficient_add = a[equation_index][var_index] *  old_no_basic_var_coefficient
                    a[i][var_index] += coefficient_add
                # 带入后之前选定的非基本变量系数设为0
                a[i][no_basic_var] = 0
        
        # 检查此次迭代是否改变了w值
        if abs(w_last - a[-1][-1]) < 1e-5:
            not_change_count += 1
            if not_change_count >= 10:
                return w_last
        if a[-1][-1] - w_last < 0:
            print("warning: w decreased")
        
        # 一轮迭代完成
        print(np.round(a, 2))

def main():
    m = findMaxW(a)
    print(m)

if __name__ == "__main__":
    main()

    

        


        
    
        



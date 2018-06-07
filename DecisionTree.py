import math;
from math import ceil;
import collections;
import matplotlib.pyplot as plt;

#PRESHEN GOOBIAH, MARC KARP, SHAYLIN PILLAY
class Node:
    def __init__(self, subset, parent, subset_value):
        self.subset = subset
        self.parent = parent
        self.list_children = [];
        self.column_num = -1;
        self.subset_value = subset_value
    
    
    def set_column_num(self, column_num, name):
        self.column_num = column_num
        self.name = name
    
    
    def append_child(self, child):
        self.list_children.append(child)

#***********************************************************************************************************#

#GLOBAL VARIABLES & HYPERPARAMETERS
#entropy_threshold = 0.1

list_nodes=[] # LIST OF ALL NODES IN THE TREE
distinct_values_of_column = [2,3,2,
                             2,2,3,
                             3,3,3,
                             2,2,2,
                             2,3,3,
                             2,2,2,
                             2,2,2,
                             2,2,3,
                             2,3,3,
                             2,3,2,
                             ]
train_percentage = 0.7
validate_percentage = 0.1
all_data = [];
columns = ["has_ip","long_url","short_service","has_at","double_slash_redirect","pref_suf","has_sub_domain","ssl_state","long_domain","favicon","port","https_token","req_url","url_of_anchor","tag_links","SFH","submit_to_email","abnormal_url","redirect,mouseover" ,"right_click","popup","iframe","domain_Age","dns_record","traffic","page_rank","google_index","links_to_page","stats_report"]

#CGLOBAL VARIABLES END
#storing number of values that an attribute can take on, not necessarily in training set
# we need these to turn nodes, which we dont split up into the subsets that it should have, into leafs


def entropy(set_):
    #work out entropy for given subset
    num_phishing = 0.0
    num_legit = 0.0
    set_length = float(len(set_))
    
    target_attribute = len(set_[0])-1

    for row in set_:
        if(row[target_attribute] == '1' ):
            num_legit += 1
        else:
            num_phishing += 1

    entropy_calc = 0.0;
    if(num_legit/set_length == 0 and num_phishing/set_length == 0):
        return 0
    elif(num_legit/set_length == 0):
    
        entropy_calc = -((num_phishing/set_length) * math.log(num_phishing/set_length,2))

    elif(num_phishing/set_length == 0):
    
       entropy_calc =  -((num_legit/set_length) * math.log(num_legit/set_length,2))

    else:
        entropy_calc = -((num_legit/set_length) * math.log(num_legit/set_length,2)+
                         (num_phishing/set_length) * math.log(num_phishing/set_length,2));



    return entropy_calc


def distinct_values(column_num,subset):
    #get distinct values for a specific attribute
    distinct_list = [];
    for row in subset:
        if row[column_num] not in distinct_list:
            distinct_list.append(row[column_num])
    return distinct_list



def potential_entropy(num_phishing, num_legit, num_distinct):
    #takes in number of phising and legit then calculates entropy
    set_length = num_phishing+num_legit
    num_phishing = num_phishing
    num_legit = num_legit
    
    entropy_calc = 0.0
    
    if(num_legit/set_length == 0 and num_phishing/set_length == 0):
        return 0
    elif(num_legit/set_length == 0):
    
        entropy_calc = -((num_phishing/set_length) * math.log(num_phishing/set_length,2))
    
    elif(num_phishing/set_length == 0):
        
        entropy_calc =  -((num_legit/set_length) * math.log(num_legit/set_length,2))
    
    else:
        entropy_calc = -((num_legit/set_length) * math.log(num_legit/set_length,2)+
                         (num_phishing/set_length) * math.log(num_phishing/set_length,2));


    return entropy_calc



def information_gain(column_num, subset):
    gain = 0.0
    set_length = float(len(subset))
    target_attribute = len(subset[0])-1
    list_distinct_values = distinct_values(column_num, subset)
    initial_entropy =entropy(subset)
    for value in list_distinct_values:
        num_phishing = 0.0;
        num_legit = 0.0;
        for row in subset:
            if row[column_num] == value:
                if row[target_attribute] == '1':
                    num_legit = num_legit+1;
                else:
                    num_phishing = num_phishing+1;
    
        total_rows = num_phishing + num_legit
        gain = gain + ((total_rows/set_length) *
                       potential_entropy(num_phishing, num_legit, len(list_distinct_values)))

    info_gain = initial_entropy-gain
    
    
    
    return info_gain


def best_attribute(set_):
    # look at all gains for given columns then find max
    list_information_gain =[];


    for col_num in range (0,len(set_[0])-1): #DONT LOOK AT TARGET
        
        list_information_gain.append(information_gain(col_num, set_))
            
        best_attribute = list_information_gain.index(max(list_information_gain))
            
    return best_attribute



def get_subsets(column_num, set_):
    list_subset = []
    # get subsets if you split on the values of the attribute with the most gain
    # these subsets are stored in a list of subsets for every distinct value the best attribute can have
    # eg. SSL {-1,0,1} -> we have 3 subsets where each subset has a SSL value of -1 OR 0 OR 1
    list_distinct_values = distinct_values(column_num, set_)
    

    for value in list_distinct_values:
        subset = []
        for row in set_:
            if row[column_num] == value:
                subset.append(row)
        list_subset.append(subset)

    return list_subset

def pure_subset(set_):
    
    if(entropy(set_) < entropy_threshold):
        return True
    else:
        return False;



def calc_majority(subset):
    count_phishing= 0.0
    count_legit= 0.0
    for row in subset:
        if row[len(subset[0])-1] is '1':
            count_legit +=1
        else:
            count_phishing +=1

    if(count_legit>count_phishing):
        return "Legit"
    else:
        return "Phishing"


def create_node(subset, node):
    if(node is None):
        node = Node(subset,None, None)
    
    best_column = best_attribute(node.subset)
    node.set_column_num(best_column, columns[best_column]) # set column number and name from data set of node
    
    if len(get_subsets(node.column_num, node.subset)) == distinct_values_of_column[node.column_num]: #checls of there is any subsets that return ----- ONLY CREATE CHILDREN FOR NODES, WHEN TEST DATA HAS ALL REQUIRED ATTRIBUTES - if not can encounter this with test data causes crash
        for subset in get_subsets(node.column_num, node.subset):
            child = Node(subset, node, subset[0][node.column_num]) # set distinct value of a node to be distinct value we can have for parent
            node.append_child(child)
    else:
        node.column_num =-2 #leaf node
        node.name = calc_majority(subset); # make it a leaf if its not a pure subset but we cant split on this attrbibute
    # node.subset_value = node.subset[0][node.parent.column_num]

    list_nodes.append(node) # store all nodes


    for child in node.list_children:
        if(pure_subset(child.subset) == True ):
            child.column_num = -2
            child.name = calc_majority(subset);
            #child.subset_value = child.subset[0][child.parent.column_num] #make it a lead node if its a pure subset
            
            continue #skip these nodes
        else:
            
            create_node(child.subset, child)
    return

visited = []

def dfs(graph, node, visited):
    if node not in visited:
        
        visited.append(node.name+ " " + str(distinct_values_of_column[node.column_num]) + " "+str(node.column_num)+ " ")
        for n in node.list_children:
            dfs(graph,n, visited)
    return visited


def predictor(row):
    
    node= list_nodes[0]
    count = 0;
    
    while len(node.list_children) > 0:
        child = node.list_children[count]
        value =row[node.column_num]
        #print("xxxxxxx")
        #print("Parent Node name: " + node.name + " has Children: ")
        #print([child2 for child2 in node.list_children])
        #print([child3.name for child3 in node.list_children])
        # print("With subset values: ")
        # print([child3.subset_value for child3 in node.list_children])
        # print("Compare: " + str(value) + " with " + child.name + ", subset value: " + str(child.subset_value))
        if(value == child.subset_value):
            node = child;
            count = 0;
        else:
            count = count+1;
        
        if(node.name=="Phishing" or node.name=="Legit"):
            return node.name
# print("xxxxxxx")


def build_tree(test_data):
    create_node(test_data,None)


#************************************************************************#
#read data from textfile and put it in  array

def read_data():
    file = open("ML_ASSIGNMENT_DATA.txt","r");
    lines = file.read().split("\n");
    for x in lines:
        row_array = x.split(",")
        all_data.append(row_array)

def train_validation_test_data(all_data):
    split_data = []
    data_length = len(all_data)
    
    train = int(ceil((train_percentage) * data_length))
    validate = int(validate_percentage * data_length)
    
    train_data = []
    validation_data = []
    test_data = []
    
    for i in range(0,  train):
        train_data.append(all_data[i])
    
    for i in range(train, train+validate):
        validation_data.append(all_data[i])

    for i in range(train+validate, data_length):
        test_data.append(all_data[i])
    
    split_data.append(train_data)
    split_data.append(validation_data)
    split_data.append(test_data)
    
    return split_data


def accuracy(data_to_report_on):
    accurate = 0.0
    target_attribute = len(data_to_report_on[0])-1
    total_phishing = 0;
    for x in data_to_report_on:
        if(predictor(x) == "Phishing" and x[target_attribute] == "-1"):
            accurate += 1
        elif(predictor(x) == "Legit" and x[target_attribute] == "1"):
            accurate +=1
#print(len(data_to_report_on))
    return (accurate/float(len(data_to_report_on)))


def confusion_matrix(data_to_report_on):
    predicated_phishing_got_phishing = 0.0
    predicated_phishing_got_legit= 0.0
    
    predicated_legit_got_legit =0.0
    predicated_legit_got_phishing=0.0
    
    target_attribute = len(data_to_report_on[0])-1
    total_phishing = 0;
    for x in data_to_report_on:
        if(predictor(x) == "Phishing" and x[target_attribute] == "-1"):
            predicated_phishing_got_phishing+=1
        
        if(predictor(x) == "Phishing" and x[target_attribute] == "1"):
            predicated_phishing_got_legit +=1
        
        if(predictor(x) == "Legit" and x[target_attribute] == "-1"):
            predicated_legit_got_phishing +=1

        if(predictor(x) == "Legit" and x[target_attribute] == "1"):
            predicated_legit_got_legit+=1;
    
    print("{} {} {}".format("\t", "Legit", "Phishing"))
    print("{} {} {}".format("Legit\t", predicated_legit_got_legit, predicated_legit_got_phishing))
    print("{} {} {}".format("Phishing ", predicated_phishing_got_legit, predicated_phishing_got_phishing))


#for x in data_to_report_on:
#print("Actual Class: " , x[target_attribute], "Predicted Class: ", predictor(x))


accuracy_train = []
entropy_used = []
entropy_threshold = 0.0
# CALL "MAIN" FUNCTIONS

read_data()
split_data = train_validation_test_data(all_data)


print(len(split_data[0]))
print(len(split_data[1]))
print(len(split_data[2]))

for x in range(0,1):
    entropy_threshold += 0.01
    entropy_used.append(entropy_threshold)
    build_tree(split_data[0])
    accuracy_train.append(accuracy(split_data[0]))
    list_nodes.clear()

accuracy_validation = []
entropy_threshold = 0.0
for x in range(0,1):
    entropy_threshold += 0.01
    build_tree(split_data[0])
    accuracy_validation.append(accuracy(split_data[1]))
    # print(accuracy_test)
    list_nodes.clear()



plt.plot(entropy_used, accuracy_train, "g", entropy_used, accuracy_validation, "b")
plt.xlabel("Entropy Threshold")
plt.ylabel("Accuracy")
plt.legend(["Train", "Validation"])
plt.title("Training & Validation Accuracy vs Change in Entropy Threshold")
#plt.show()


entropy_threshold = 0.13
build_tree(split_data[0])
confusion_matrix(split_data[2])
print(accuracy(split_data[2]))





from math import ceil
import matplotlib.pyplot as plt

#MARC KARP, PRESHEN GOOBIAH, SHAYLIN PILLAY
attribute_list=[]
laplacian_add = 0.0

train_percentage = 0.7
validate_percentage = 0.1

list_distinct_values=[["1","0"],["1","0","-1"],["1","0"],
                      ["1","0"],["1","0"],["1","0","-1"],
                      ["1","0","-1"],["1","0","-1"],["1","0","-1"],
                      ["1","0"],["1","0"],["1","0"],
                      ["1","-1"],["1","0","-1"],["1","0","-1"],
                      ["1","-1"],["1","0"],["1","0"],
                      ["1","0"],["1","0"],["1","0"],
                      ["1","0"],["1","0"],["1","0","-1"],
                      ["1","0"],["1","0","-1"],["1","0","-1"],
                      ["1","0"],["1","0","-1"],["1","0"]]

class Attribute:
    
    def __init__(self, column_number):
        self.column_number = column_number
        self.distinct_values = list_distinct_values[column_number]
        self.list_probs=[]


    def append_probs(self,prob):
        self.list_probs.append(prob)

def read_data():
    all_data=[]
    file = open("ML_ASSIGNMENT_DATA.txt","r")
    lines = file.read().split("\n")
    for x in lines:
        row_array = x.split(",")
        all_data.append(row_array)
    return all_data

def setup_attributes():
    for index in range(0,30):
        attribute = Attribute(index)
        attribute_list.append(attribute)

def learn_probs_and_priors(training_data):
    attribute_index=-1
    count_legit = 0.0
    count_phishing =0.0
    
    for row in training_data:
        if(row[len(training_data[0])-1]=="1"):
            count_legit+= 1
        else:
            count_phishing+=1

    prob_legit = count_legit/(count_phishing+count_legit)
    prob_phishing = count_phishing/(count_legit+count_phishing)

    for attribute_distinct in list_distinct_values:
        attribute_index += 1
        for value in attribute_distinct:
            count_value_legit = 0.0+laplacian_add
            count_value_phishing=0.0+ laplacian_add
            for row in training_data:
                if(row[attribute_index]==value):
                    if(row[len(training_data[0])-1]=="1"):
                        count_value_legit+= 1
                    else:
                        count_value_phishing+=1
        

#attribute_list[attribute_index].append_probs([count_value_legit/(count_legit+len(attribute_distinct)), count_value_phishing/(count_phishing+len(attribute_distinct))])
            attribute_list[attribute_index].append_probs([count_value_legit/(count_legit + laplacian_add*2), count_value_phishing/(count_phishing + laplacian_add*2)])

    return [prob_legit, prob_phishing]


def naive_bayes_predictor(row, priors):
    class_conditional_phishing = 1.0
    class_conditional_legit = 1.0
    
    prior_legit = priors[0]
    prior_phishing = priors[1]

    for i in range(0, len(row)-1):
        attribute = attribute_list[i]
        
        row_attribute_value = row[i]
        for value in attribute.distinct_values:
            if row_attribute_value == value:
                index_distinct = attribute.distinct_values.index(value)
                class_conditional_legit = class_conditional_legit * attribute.list_probs[index_distinct][0]
                class_conditional_phishing = class_conditional_phishing * attribute.list_probs[index_distinct][1]
                break
        prob_normalisation = (class_conditional_legit* prior_legit) + (class_conditional_phishing*prior_phishing)

    posterior_legit = (class_conditional_legit * prior_legit)/prob_normalisation
    posterior_phishing = (class_conditional_phishing*prior_phishing)/prob_normalisation

    if posterior_legit > posterior_phishing:
        return "LEGIT"
    else:
        return "PHISHING"

def confusion_matrix(data_to_report_on, priors):
    predicated_phishing_got_phishing = 0.0
    predicated_phishing_got_legit= 0.0
    
    predicated_legit_got_legit =0.0
    predicated_legit_got_phishing=0.0
    
    target_attribute = len(data_to_report_on[0])-1
    total_phishing = 0;
    for x in data_to_report_on:
     
        if(naive_bayes_predictor(x, priors) == "PHISHING" and x[target_attribute] == "-1"):
            predicated_phishing_got_phishing+=1
        
        if(naive_bayes_predictor(x, priors)== "PHISHING" and x[target_attribute] == "1"):
            predicated_phishing_got_legit +=1
        
        if(naive_bayes_predictor(x, priors)== "LEGIT" and x[target_attribute] == "-1"):
            predicated_legit_got_phishing +=1
        
        if(naive_bayes_predictor(x, priors) == "LEGIT" and x[target_attribute] == "1"):
            predicated_legit_got_legit+=1;
    
    print("{} {} {}".format("\t", "Legit", "Phishing"))
    print("{} {} {}".format("Legit\t", predicated_legit_got_legit, predicated_legit_got_phishing))
    print("{} {} {}".format("Phishing ", predicated_phishing_got_legit, predicated_phishing_got_phishing))

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


##################
#Main
###################

all_data= read_data()
setup_attributes()

accuracy_validate = []
percent_train = []

accuracy_train = []

for i in range(0,99):
    laplacian_add += 0.01
    list_train_validate_test = train_validation_test_data(all_data)
    priors = learn_probs_and_priors(list_train_validate_test[0])
    accuracy = 0.0
    for a in list_train_validate_test[1]:
        if(a[30] == "1" and  naive_bayes_predictor(a, priors) == "LEGIT"):
            accuracy+=1
        elif(a[30] == "-1" and naive_bayes_predictor(a, priors) == "PHISHING"):
            accuracy+=1
    accuracy = accuracy/len(list_train_validate_test[1])
    accuracy_validate.append(accuracy)
    percent_train.append(train_percentage)

laplacian_add = 0.00001
laplacian_list=[]
for i in range(0,99):
    laplacian_add += 0.01
    laplacian_list.append(laplacian_add)
    list_train_validate_test = train_validation_test_data(all_data)
    priors = learn_probs_and_priors(list_train_validate_test[0])
    accuracy = 0.0
    for a in list_train_validate_test[0]:
        if(a[30] == "1" and  naive_bayes_predictor(a, priors) == "LEGIT"):
            accuracy+=1
        elif(a[30] == "-1" and naive_bayes_predictor(a, priors) == "PHISHING"):
            accuracy+=1
    accuracy = accuracy/len(list_train_validate_test[0])
    accuracy_train.append(accuracy)



laplacian_add = 0.2
priors = learn_probs_and_priors(list_train_validate_test[0])
accuracy = 0.0
for a in list_train_validate_test[2]:
    if(a[30] == "1" and  naive_bayes_predictor(a, priors) == "LEGIT"):
        accuracy+=1
    elif(a[30] == "-1" and naive_bayes_predictor(a, priors) == "PHISHING"):
        accuracy+=1
accuracy_test = accuracy/len(list_train_validate_test[2])

print("Accuracy of test: ", accuracy_test)


plt.plot(laplacian_list, accuracy_train, "g", laplacian_list, accuracy_validate, "b")
plt.xlabel("Laplacian")
plt.ylabel("Accuracy")
plt.legend(["Train", "Validation"])
plt.title("Train & Validation vs change in Laplacian Smoothing")
plt.show()



confusion_matrix(list_train_validate_test[2],priors)


                      
                      
                      
                      
                      
                      
                      
                      
                      

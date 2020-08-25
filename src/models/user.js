const mongoose = require('mongoose')
const validator = require('validator')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const Task = require('./task')

const userSchema = mongoose.Schema({
	name: {
		type: String,
		required: true,
		trim: true
	},
	email: {
		type:String,
		required: true,
		unique: true,
		trim: true,
		lowercase: true,
		validate(value) {
			if(!validator.isEmail(value)) {
				throw new Error('Email is invalid')
			}
		}

	},
	password: {
		type: String,
        required: true,
        minlength: 7,
        trim: true,
        validate(value) {
            if (value.toLowerCase().includes('password')) {
                throw new Error('Password cannot contain "password"')
            }
        }
	},
	age: {
		type: Number,
        default: 0,
        validate(value) {
            if (value < 0) {
                throw new Error('Age must be a postive number')
            }
        }

	},
	tokens: [{
		token:{
			type: String,
			required: true
		}
	}],
	avatar: {
		type: Buffer
	}
}, {
		timestamps: true
	})


userSchema.virtual('tasks', {
	ref: 'Task',
	localField: '_id',  //this field is related to User model which should be equal to foreignField
	foreignField: 'owner' //this field is related to Task model.
	//where this two field meets or become equal that document is populated (document means item of model)
})


userSchema.methods.toJSON = function() {
	const user = this

	const userObject = user.toObject()
	
	delete userObject.password
	delete userObject.tokens


	return userObject

}

userSchema.methods.generateToken = async function() {
	const user = this

	const token = await jwt.sign({_id : user._id.toString()}, process.env.JWT_SECRET)
	user.tokens = user.tokens.concat({token})

	await user.save()

	return token
}

userSchema.statics.findByCredentials = async (email, password) => {
	const user = await User.findOne({email})

	if(!user) {
		throw new Error('Unable to login')
	}

	const isMatch = await bcrypt.compare(password, user.password)

	if(!isMatch) {
		throw new Error('Unable to login') 
	}

	return user

}

//Hashing password before saving
userSchema.pre('save' , async function(next) {
	const user = this  // here this refers to the object which we wants to save eg object.save() now this  will refer to object attached to save function

	if(user.isModified('password')) {
		user.password = await bcrypt.hash(user.password, 8)
	} 

	next()
})

//Delete user task when user is deleted

userSchema.pre('remove', async function(next) {
	const user = this  // here this refers to the object which we wants to remove eg object.remove() now this  will refer to object attached to remove function
	console.log(user)

	await Task.deleteMany({owner:user._id})

	next()
})


const User = mongoose.model('User', userSchema)


module.exports = User